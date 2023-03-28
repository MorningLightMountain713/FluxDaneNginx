import asyncio
from pathlib import Path

import yaml
from fluxvault import FluxAppManager, FluxKeeper, AppMode

from jinja2 import Environment, FileSystemLoader

from dane import DaneRunner, dns_extensions, nginx_extensions

with open("user_config.yaml", "r") as stream:
    user_config: dict = yaml.safe_load(stream)


nginx_app_name = user_config.get("nginx_app_name")
dns_app_name = user_config.get("dns_app_name")
handshake_domain = user_config.get("handshake_domain")
tls_port = user_config.get("tls_port")

# this template stuff is just a hack until I build the template stuff properly

TEMPLATE_DIR = Path("templates")

TEMPLATE_MAP = {
    "nginx_proxy.jinja": {
        "remote_name": user_config.get("handshake_domain"),
        "remote_dir": "vault/DaneNginx/components/proxy/fake_root/etc/nginx/sites-enabled",
    },
    "pdns_runner.py.jinja": {
        "remote_name": "pdns_runner.py",
        "remote_dir": "vault/DNSDriver/components/dns_agent/fake_root/var/lib/fluxvault/plugins",
    },
}

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
for template_name in env.list_templates():
    template = env.get_template(template_name)
    output = template.render(user_config)

    path = (
        Path(TEMPLATE_MAP[template_name]["remote_dir"])
        / TEMPLATE_MAP[template_name]["remote_name"]
    )
    with open(path, "w") as stream:
        stream.write(output)


def main():
    dns_app_config = {
        "app_config": {
            "comms_port": user_config.get("dns_server_comms_port"),
            "fluxnode_ips": user_config.get("dns_server_ips"),
            "app_mode": AppMode.SINGLE_COMPONENT,
            "extensions": dns_extensions,
        },
        "components": {
            "dns_agent": {
                "state_directives": [
                    {
                        "name": "pdns_runner.py",
                        "remote_dir": "/var/lib/fluxvault/plugins",
                        "sync_strategy": "STRICT",
                    },
                    {
                        "name": "pdns.py",
                        "remote_dir": "/var/lib/fluxvault/plugins",
                        "sync_strategy": "STRICT",
                    },
                ],
                "remote_workdir": "/tmp",
            },
        },
    }
    nginx_app_config = {
        "app_config": {
            # "fluxnode_ips": ["127.0.0.1"],
            "comms_port": user_config.get("nginx_app_comms_port"),
            "app_mode": AppMode.SINGLE_COMPONENT,
            "extensions": nginx_extensions,
        },
        "components": {
            "proxy": {
                "state_directives": [
                    {
                        "name": "nginx.py",
                        "remote_dir": "/var/lib/fluxvault/plugins",
                        "sync_strategy": "STRICT",
                    }
                ],
                "remote_workdir": "/tmp",
            },
        },
    }

    dns_app = FluxKeeper.build_app(
        dns_app_name, Path("vault") / dns_app_name, dns_app_config
    )
    nginx_app = FluxKeeper.build_app(
        nginx_app_name, Path("vault") / nginx_app_name, nginx_app_config
    )

    keeper = FluxKeeper(apps=[nginx_app, dns_app])

    danenginx: FluxAppManager = keeper.get_app_manager_by_name(nginx_app_name)
    dnsdriver: FluxAppManager = keeper.get_app_manager_by_name(dns_app_name)

    dane = DaneRunner(danenginx, dnsdriver, f"{handshake_domain}.", tls_port)

    asyncio.run(dane.run_forever())


if __name__ == "__main__":
    main()
