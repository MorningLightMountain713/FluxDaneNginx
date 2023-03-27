import asyncio
import pickle
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable

import cryptography
from cryptography.x509.oid import NameOID
from fluxrpc.client import RPCClient
from fluxvault import FluxAppManager, FluxKeeper
from fluxvault.extensions import FluxVaultExtensions
from fluxvault.helpers import (
    ContainerState,
    FluxTask,
    FluxVaultContext,
    manage_transport,
)
from fluxvault.log import log
from ownca.exceptions import OwnCAInvalidCertificate
from rich.pretty import pretty_repr


@dataclass
class RRSet:
    name: str
    rtype: str
    records: field(default_factory=list)

    @classmethod
    def from_dict(target: dict):
        return RRSet(**target)

    def encode(self):
        return self.__dict__


CONTACT_SCHEDULE = 60  # seconds
SYNC_OBJECTS_SCHEDULE = 5 * CONTACT_SCHEDULE
AGENT_ID_TO_TLSA_FILE = Path(".dane_tlsa_address_mapping")

nginx_extensions = FluxVaultExtensions()
dns_extensions = FluxVaultExtensions()


@dns_extensions.create()
@nginx_extensions.create()
@manage_transport
async def load_agents_plugins(agent):
    agent_proxy = agent.get_proxy()
    await agent_proxy.load_plugins()


@nginx_extensions.create()
@manage_transport
async def start_agents_nginx(agent: RPCClient):
    agent_proxy = agent.get_proxy(plugins=["nginx"])
    # await agent_proxy.nginx.start()
    await agent_proxy.nginx.reload_config()


@nginx_extensions.create()
@manage_transport
async def install_nginx(agent: RPCClient):
    agent_proxy = agent.get_proxy(plugins=["nginx"])
    await agent_proxy.nginx.install()


@nginx_extensions.create()
@manage_transport
async def commit_seppuku(agent: RPCClient):
    agent_proxy = agent.get_proxy(plugins=["nginx"])
    agent_proxy.notify()
    await agent_proxy.nginx.commit_seppuku()


@nginx_extensions.create(pass_context=True)
@manage_transport
async def install_nginx_certs(ctx: FluxVaultContext, agent: RPCClient) -> bytes:
    proxy = agent.get_proxy()

    res = await proxy.generate_csr("davidwhite", "nginx.pem")
    csr_bytes = res.get("csr")

    csr = cryptography.x509.load_pem_x509_csr(csr_bytes)
    hostname = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    try:
        cert = ctx.ca.load_certificate(hostname)
        ctx.ca.revoke_certificate(hostname)
    except OwnCAInvalidCertificate:
        pass
    finally:
        root_dir = FluxKeeper.setup()
        # ToDo: there has to be a better way (don't delete cert)
        # start using CRL? Do all nodes need CRL - probably
        shutil.rmtree(root_dir / f"ca/certs/{hostname}", ignore_errors=True)
        cert = ctx.ca.sign_csr(csr, csr.public_key())

    await proxy.install_cert(cert.cert_bytes, "nginx.crt")

    return cert.cert_bytes


@dns_extensions.create()
@manage_transport
async def get_agents_dns_records(agent: RPCClient, zone_name: str) -> list:
    proxy = agent.get_proxy(plugins=["pdns"])

    return await proxy.pdns.list_records(zone_name)


@dns_extensions.create()
@manage_transport
async def remove_agents_dns_records(
    agent: RPCClient,
    zone_name: str,
    port: str,
    tlsa_records: list[str],
    a_records: list[str],
):
    proxy = agent.get_proxy(plugins=["pdns"])

    tlsa_record_name = f"_{port}._tcp.{zone_name}"
    tlsa_rrset = RRSet(tlsa_record_name, "TLSA", tlsa_records).encode()
    a_rrset = RRSet(zone_name, "A", a_records).encode()

    await proxy.pdns.remove_records(zone_name, [tlsa_rrset, a_rrset])


@dns_extensions.create()
@manage_transport
async def add_agents_dns_records(
    agent: RPCClient,
    zone_name: str,
    port: int,
    tlsa_records: list[str],
    a_records: list[str],
):
    proxy = agent.get_proxy(plugins=["pdns"])

    tlsa_record_name = f"_{port}._tcp.{zone_name}"
    tlsa_rrset = RRSet(tlsa_record_name, "TLSA", tlsa_records).encode()
    a_rrset = RRSet(zone_name, "A", a_records).encode()

    await proxy.pdns.add_records(zone_name, [tlsa_rrset, a_rrset])


class DaneRunner:
    def __init__(
        self,
        danenginx: FluxAppManager,
        dnsdriver: FluxAppManager,
        zone_name: str,
        tls_port: int,
    ):
        self.danenginx = danenginx
        self.dnsdriver = dnsdriver
        self.first_run = True
        self.time_since_last_sync: dict[tuple, int] = {}
        self.uncontactable_count: dict[tuple, int] = {}
        self.zone_name = zone_name
        self.tls_port = tls_port  # The port that you connect to the webserver on. Usually 443 but Flux, custom
        self.active_nginx_nodes: set[tuple] = set()
        self.all_nginx_nodes: set[tuple] = set()
        self.record_map: dict[tuple, dict[tuple, str]] = {}

        if AGENT_ID_TO_TLSA_FILE.exists() and AGENT_ID_TO_TLSA_FILE.stat().st_size > 0:
            with open(AGENT_ID_TO_TLSA_FILE, "rb") as stream:
                try:
                    # use pickle instead of json here as json cant encode tuple as dict key
                    self.record_map = pickle.load(stream)
                    log.info(f"Record mapping: {pretty_repr(self.record_map )}")

                except pickle.PickleError:
                    log.error(
                        f"Unable to parse record map... something bad happened. Maybe delete {AGENT_ID_TO_TLSA_FILE} and try again"
                    )

        # maybe? (update to record map)

        # self.a_map = data.get("a", {})
        # self.tlsa_map = data.get("tlsa", {})

        # for agent_id in self.a_map.keys():
        # If we've just started and we have existing file, give nodes the benefit of the doubt
        # self.active_nginx_nodes.add(agent_id)

    @staticmethod
    def key_by_value(subject: dict, value):
        for k, v in subject.items():
            if v == value:
                return k

    @staticmethod
    async def generate_tlsa(cert_str: str) -> str:
        """Takes a cert as a string, and returns a tlsa record in 3 1 1 format"""

        # use pyca/cryptography instead of this tomfoolery

        cmd = f'echo "{cert_str}" | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | xxd  -p -u -c 32'

        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()
        if stderr:
            print("error running subcommand")
            print(stderr)
            return ""

        stdout = stdout.decode().strip("\n")
        return f"3 1 1 {stdout}".lower()

    async def task_and_state_resolver(
        self, states: dict, task_resolver: Awaitable
    ) -> dict[tuple, list]:
        agent_tasks: dict[tuple, list] = {}
        for agent_id, state in states.items():
            tasks, time_since = await task_resolver(agent_id, state)

            self.time_since_last_sync[agent_id] = time_since
            agent_tasks[agent_id] = tasks

        return agent_tasks

    def filter_missing_records(
        self, dns_server_id: tuple, rtype: str, server_records: list
    ) -> list[str]:
        """Records that we have in our records_map but aren't on the DNS server will be added"""
        to_add = []

        for record in self.record_map[dns_server_id][rtype].values():
            if not next(
                filter(lambda x: x.get("content", None) == record, server_records),
                False,
            ):
                to_add.append(record)

        return to_add

    def filter_unknown_records(
        self, dns_server_id: tuple, rtype: str, server_records: list
    ) -> list[str]:
        """Records that exist on the DNS server but not in our records_map will be removed"""
        to_remove = []

        for record in server_records:
            record = record.get("content")
            # our record_map is the source of truth, this gets the agent_id
            if not self.key_by_value(self.record_map[dns_server_id][rtype], record):
                to_remove.append(record)

        return to_remove

    async def run_forever(self):
        await self.danenginx.start_polling_fluxnode_ips()
        # this isn't actually a fluxapp, just a powerdns server running the agent. (see dns_app_config)
        await self.dnsdriver.start_polling_fluxnode_ips()

        while True:
            dns_states: dict = await self.dnsdriver.run_agents_async(
                [self.dnsdriver.build_task("get_agents_state")], stay_connected=True
            )
            dane_states: dict = await self.danenginx.run_agents_async(
                [self.danenginx.build_task("get_agents_state")], stay_connected=True
            )

            # test what happens if dns not connected, do we just store in record map and wait?
            log.info(f"DNS states: {pretty_repr(dns_states)}")
            log.info(f"Nginx states: {pretty_repr(dane_states)}")

            self.all_nginx_nodes = set(dane_states)
            log.info(f"Available Flux Nginx nodes: {self.all_nginx_nodes}")

            # check what state each node is in (see ContainerState enum). Update our records map and build any tasks that are required
            all_nginx_agent_tasks = await self.task_and_state_resolver(
                dane_states, self.evaluate_nginx_agent_state
            )
            all_pdns_agent_tasks = await self.task_and_state_resolver(
                dns_states, self.evaluate_pdns_agent_state
            )

            # Active means node has a cert and nginx is serving
            log.info(f"active Nginx nodes: {self.active_nginx_nodes}")

            # Make sure containers are in running state, if not do configuration tasks to get them running
            nginx_task_results = await self.danenginx.run_agents_async(
                targets=all_nginx_agent_tasks
            )
            pdns_task_results = await self.dnsdriver.run_agents_async(
                targets=all_pdns_agent_tasks
            )

            # filter powerdns server(s) state for our rrsets, validate against local state (self.record_map)
            dns_agents_tasks: dict[tuple, list[FluxTask]] = {}
            for (
                dns_server_id,
                results,
            ) in (
                pdns_task_results.items()
            ):  # I've only tested on 1 dns server at a time
                if dns_server_id not in self.record_map:
                    self.record_map[dns_server_id] = {"a": {}, "tlsa": {}}

                dns_agents_tasks[dns_server_id]: list[FluxTask] = []

                nodes_to_remove = set()
                for records_by_type in self.record_map[dns_server_id].values():
                    for agent_id in list(records_by_type):
                        if agent_id not in self.all_nginx_nodes:
                            nodes_to_remove.add(agent_id)

                for node_to_remove in nodes_to_remove:
                    log.warning(
                        f"TESTING: Would normally remove {node_to_remove} as it's not in All Nginx nodes group"
                    )
                    # remove from record map, remove from dns, check self.uncontactable_count[agent_id] and remove from there too

                # this only runs on first run - just make sure remote dns matches what we have - delete any extras, add any missing
                if rrsets := results.get(
                    "get_agents_dns_records", None
                ):  # this will only be false if the server didn't respond
                    tsla_name = f"_{self.tls_port}._tcp.{self.zone_name}"

                    tlsa_rrset = next(
                        filter(
                            lambda x: x["name"] == tsla_name and x["type"] == "TLSA",
                            rrsets,
                        ),
                        {},
                    )
                    a_rrset = next(
                        filter(
                            lambda x: x["name"] == self.zone_name and x["type"] == "A",
                            rrsets,
                        ),
                        {},
                    )

                    tlsa_records = tlsa_rrset.get("records", [])
                    a_records = a_rrset.get("records", [])

                    tlsa_to_remove = self.filter_unknown_records(
                        dns_server_id, "tlsa", tlsa_records
                    )
                    a_to_remove = self.filter_unknown_records(
                        dns_server_id, "a", a_records
                    )

                    tlsa_to_add = self.filter_missing_records(
                        dns_server_id, "tlsa", tlsa_records
                    )
                    a_to_add = self.filter_missing_records(
                        dns_server_id, "a", a_records
                    )

                    log.info(f"Unknown A records to remove: {pretty_repr(a_to_remove)}")
                    log.info(
                        f"Unknown TLSA records to remove: {pretty_repr(tlsa_to_remove)}"
                    )

                    if a_to_remove or tlsa_to_remove:
                        dns_remove_task = self.dnsdriver.build_task(
                            "remove_agents_dns_records",
                            [
                                self.zone_name,
                                self.tls_port,
                                tlsa_to_remove,
                                a_to_remove,
                            ],
                        )
                        dns_agents_tasks[dns_server_id].append(dns_remove_task)

                    log.info(f"A records to add: {pretty_repr(a_to_add)}")
                    log.info(f"TLSA records to add: {pretty_repr(tlsa_to_add)}")

                    if a_to_add or tlsa_to_add:
                        dns_add_task = self.dnsdriver.build_task(
                            "add_agents_dns_records",
                            [self.zone_name, self.tls_port, tlsa_to_add, a_to_add],
                        )
                        dns_agents_tasks[dns_server_id].append(dns_add_task)

            certs: dict[tuple, str] = {}
            for agent_id, results in nginx_task_results.items():
                if cert := results.get("install_nginx_certs", None):
                    certs[agent_id] = cert

            # pprint(certs)
            if certs:  # aka change detected
                # update all dns servers

                # Before ramming the records on the dns server, first check to see if we need to remove this nodes records. (TLSA) It may
                # have just restarted
                for dns_server_id, tasks in dns_agents_tasks.items():
                    tasks.extend(
                        await self.create_records_update_state_task(
                            dns_server_id, certs
                        )
                    )

                nginx_agents_tasks: dict[tuple, list[FluxTask]] = {}
                for agent_id in certs.keys():
                    # this will reload config if nginx already running
                    nginx_agents_tasks[agent_id] = [
                        self.danenginx.build_task("start_agents_nginx")
                    ]

                await self.danenginx.run_agents_async(targets=nginx_agents_tasks)

            if any(dns_agents_tasks.values()):
                await self.dnsdriver.run_agents_async(targets=dns_agents_tasks)

            # {('DNSdriver', '116.251.187.92', 'dns_agent'): {('DaneNginx', '162.55.145.76', 'proxy'): {'a': '162.55.145.76'}}}
            with open(AGENT_ID_TO_TLSA_FILE, "wb") as stream:
                pickle.dump(self.record_map, stream)

            # shouldn't get in this state... mainly just from testing and things being broken. If things get out of sync, just restart
            # container. (FluxVault is the primary pid, so exiting process will restart container)
            rip_targets = {}
            for agent_id in self.active_nginx_nodes.copy():
                for dns_server in list(self.record_map):
                    if (
                        agent_id not in self.record_map[dns_server]["a"]
                        or agent_id not in self.record_map[dns_server]["tlsa"]
                    ):
                        log.warning(
                            f"{agent_id} running but not in record map... restarting container"
                        )
                        rip_targets[agent_id] = [
                            self.danenginx.build_task("commit_seppuku")
                        ]
                        self.active_nginx_nodes.remove(agent_id)
                        # not sure about this... records might still be out of sync, but we need to break here
                        break

            if any(rip_targets.values()):
                await self.danenginx.run_agents_async(targets=rip_targets)

            self.first_run = False

            log.info(
                f"Time since last file sync: {pretty_repr(self.time_since_last_sync)}"
            )
            log.info(f"Sleeping {CONTACT_SCHEDULE} seconds...")

            await asyncio.sleep(CONTACT_SCHEDULE)

    async def create_records_update_state_task(
        self, dns_server_id: tuple, certs: dict
    ) -> list[FluxTask]:
        a_to_add = []
        tlsa_to_add = []
        tlsa_to_remove = []
        tasks = []

        for agent_id, cert in certs.items():
            tlsa = await self.generate_tlsa(cert.decode())
            tlsa_to_add.append(tlsa)

            # Node has just restarted? (Validate this) If this happens, we only need to reload the tlsa, a remains the same
            if agent_id in self.active_nginx_nodes:
                tlsa_to_remove.append(self.record_map[dns_server_id]["tlsa"][agent_id])
            else:
                a_to_add.append(agent_id[1])

            self.record_map[dns_server_id]["tlsa"].update({agent_id: tlsa})
            self.record_map[dns_server_id]["a"].update({agent_id: agent_id[1]})

        if tlsa_to_remove:
            tasks.append(
                self.dnsdriver.build_task(
                    "remove_agents_dns_records",
                    [self.zone_name, self.tls_port, tlsa_to_remove, []],
                )
            )

        tasks.append(
            self.dnsdriver.build_task(
                "add_agents_dns_records",
                [self.zone_name, self.tls_port, tlsa_to_add, a_to_add],
            )
        )

        return tasks

    async def evaluate_nginx_agent_state(
        self, agent_id: tuple, agent_state: dict
    ) -> list:
        tasks = []

        # if we can't get from self.time_since - means we've never synced so we set this
        # to the sync_objects value to force a sync
        time_since_last_sync = self.time_since_last_sync.get(
            agent_id, SYNC_OBJECTS_SCHEDULE
        )

        if container_state := agent_state.get("get_agents_state"):
            state = ContainerState(container_state)
        else:
            state = ContainerState.UNCONTACTABLE

        match state:
            case ContainerState.RUNNING:
                if not agent_id in self.active_nginx_nodes:
                    # node has been remove due to connection failure, but obviously we have connected again
                    # maybe implement standdown period? Like has to maintain 3 connects or something?
                    self.active_nginx_nodes.add(agent_id)

                time_since_last_sync += CONTACT_SCHEDULE

                if time_since_last_sync >= SYNC_OBJECTS_SCHEDULE:
                    tasks.append(self.danenginx.build_task("sync_objects"))
                    time_since_last_sync = 0
                else:
                    await self.danenginx.disconnect_agent_by_id(agent_id)

                if agent_id in self.uncontactable_count:
                    del self.uncontactable_count[agent_id]

            case ContainerState.DEFAULT:
                # it is possible to go straight from RUNNING state to DEFAULT. In this case, we need to remove the dns records
                for task in [
                    "set_mode",
                    "sync_objects",
                    "load_agents_plugins",
                    "install_nginx",
                    "install_nginx_certs",
                ]:
                    tasks.append(self.danenginx.build_task(task))

                time_since_last_sync = 0

                if agent_id in self.uncontactable_count:
                    del self.uncontactable_count[agent_id]

                # if the node is defaulted, remove records from the map
                # we don't need to do this here, just wait until the new cert and overwrite the map then

                # for dns_server in list(self.record_map):
                #     try:
                #         del self.record_map[dns_server]["a"][agent_id]
                #         del self.record_map[dns_server]["tlsa"][agent_id]
                #     except KeyError:
                #         pass

            case ContainerState.UNCONTACTABLE:
                # 1 miss + 2 retries
                if retries := self.uncontactable_count.get(agent_id, 0) >= 2:
                    if agent_id in self.active_nginx_nodes:
                        log.warn(
                            f"Node {agent_id} has missed 3 contacts... remove from active Nginx nodes"
                        )
                        self.active_nginx_nodes.remove(agent_id)
                else:
                    self.uncontactable_count[agent_id] = retries + 1

            case ContainerState.ERROR:
                # restart_container. This needs App deployer key so we can login (fix remaining bugs in FluxWallet first)
                await self.danenginx.disconnect_agent_by_id(agent_id)

            case ContainerState.STOPPED:
                # only get stopped if we set it (currently we don't)
                await self.danenginx.disconnect_agent_by_id(agent_id)

        return tasks, time_since_last_sync

    async def evaluate_pdns_agent_state(
        self, agent_id: tuple, all_state: dict
    ) -> tuple:
        tasks = []

        time_since_last_sync = self.time_since_last_sync.get(
            agent_id, SYNC_OBJECTS_SCHEDULE
        )

        if agent_state := all_state.get("get_agents_state"):
            state = ContainerState(agent_state)
        else:
            state = ContainerState.UNCONTACTABLE

        match state:
            case ContainerState.RUNNING:
                log.info(f"Existing node {agent_id} found")
                time_since_last_sync += CONTACT_SCHEDULE

                if time_since_last_sync >= SYNC_OBJECTS_SCHEDULE:
                    tasks.append(self.dnsdriver.build_task("sync_objects"))
                    time_since_last_sync = 0

                if self.first_run:
                    tasks.append(
                        self.dnsdriver.build_task(
                            "get_agents_dns_records", [self.zone_name]
                        )
                    )

                else:
                    await self.dnsdriver.disconnect_agent_by_id(agent_id)

            case ContainerState.DEFAULT:
                log.info(f"New node {agent_id} found")
                for task in ["set_mode", "sync_objects", "load_agents_plugins"]:
                    tasks.append(self.dnsdriver.build_task(task))
                    time_since_last_sync = 0

                if self.first_run:
                    tasks.append(
                        self.dnsdriver.build_task(
                            "get_agents_dns_records", [self.zone_name]
                        )
                    )

            case ContainerState.UNCONTACTABLE:
                ...

            case ContainerState.ERROR:
                # restart_container(agent_id)
                await self.dnsdriver.disconnect_agent_by_id(agent_id)

            case ContainerState.STOPPED:
                await self.dnsdriver.disconnect_agent_by_id(agent_id)

        return tasks, time_since_last_sync
