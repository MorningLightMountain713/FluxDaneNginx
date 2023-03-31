from pdns_nginx import dane
from unittest.mock import patch, call
import pytest
import asyncio
import pickle
from pathlib import Path
from rich.pretty import pretty_repr
from functools import partial

zone = "testzone."
tls_port = 33443

new_cert = b"""-----BEGIN CERTIFICATE-----
MIIFOTCCAyOgAwIBAgIFBCAkBmswCwYJKoZIhvcNAQELMBUxEzARBgNVBAMMCndl
aW5lcnRvd24wHhcNMjMwMzI4MjMyNjQ3WhcNMjMwMzMxMjMyNjQ3WjAVMRMwEQYD
VQQDDAp3ZWluZXJ0b3duMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
l41C5jYL6WQQJuPQTq1DXonHD74Lcwak7SAVx0FRxfzJKYurRJH0nPHELM1m3fqs
xedprTIYr5Z1zXocA0cS0jkn7xarfGmelKE84wXRL7TplXbbzZwlwI1g+gdOCNkY
xvFx5cw74njRmKuQ2ZORm4Xcy9y1LcvXPA1lI+l30ge+CikvVDiY0E4CsIcA1Qtq
wpVuq4smgjDdd+mwY2tC5hyv35jLug5PHzBF1bnZ/31tYQj1o0uUgGX5wD+YP16S
KW+P22OHcbs+w0JF6YJ3+RgX7P3CSbu/Cxc4pG5Zxrn9DnMKcWvyQ3gjqLUnDYCD
9vLriCmMSEGKx1J/+n3DTy9J888GSLjoSF73W5DoWUf8aaYqsRWu64MRTw+3gH5S
XpPkeXIHLM3PnmbgaNCkUyYBL0AgYqKANPed/gCTy+mlW6DvgQ1m+EibdI5O90sV
v/FAO99Juqx58pZikohV/lMjD39/106xXOHsxRQ2yYVP5hi7ncdOq7WXI+gCc87w
7R/Us33hcR8aM2IN77ra6Ny9Ziax97aHTLaiujS8IEVnJ1vYh01aN5lw7AaTgPhT
/RyebDbiioP1SNj79IKrEhvDUM4yvVCUUr7TYM/ZtUFRLSLNrv5Zq7r45lbcKZoX
ZZ5KlIf9tKw8e/hM0kw3Dyd377Hnrpxdl4Pt32nztL0CAwEAAaOBkzCBkDAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIAoDATBgNVHSUEDDAKBggrBgEFBQcDATBb
BgNVHREEVDBSggp3ZWluZXJ0b3duggxzYXVzYWdlY2hvcHOCCmdyYXZ5dHJhaW6C
DCoud2VpbmVydG93boIOKi5zYXVzYWdlY2hvcHOCDCouZ3Jhdnl0cmFpbjALBgkq
hkiG9w0BAQsDggIBAJIPmv6JujWKHghvlV40hb6XEIcVyIlmCTzer8yyF6S31ggG
+eUZPZ7pf6eOuqK6mzLBeIVgtXH65tobZNdcBx2PBbi9+Z0l77GWe+6UaO87zlIn
afqCL7WC2go06oLrD0MRM4YhqdAcDDuDCpCvKzCQdA/EQ4XgZQpqPXbLPFCffFxW
+6Be2rBlsCWMATx6LHx6H25z6Yj9CobrenUVs63ftIt3BRkYA2LXmX+7rOnWpEyX
KHNKepY5ez3H0bDB5c9hsI0g2co9w2UVbsOlI4316jz3HRhn+Qwmz7uAMf19PRDd
ATnOuttednU1NNq2xrp/H2Xx/RXUq96T7R94um+igRrYYj+vIntrTX3s3kghP3l6
Ez9HarJ6VxvMA9+UXGh2+zS4LoPPBzPAWYJ6CaXx7eoRWZhZ7TBmKgweWsi3dWJR
NdpMpXxeheuNkaaoziRUUbGpd6sVXJyQeVVI6zvM8DAWxa21EvwkrMxtR5PA1ORk
UbiSJ0rjPltVrQOc/vi9azkr/2qkh2CJN6pg56t5S5JAV0CYBtd/KAGElePtWk3y
KFKFzZENfqhcbSo6cTNSzhtsrFrwJgUe4KQol4NRuaVIlrxTiqRizEvDk+Jvkh9n
YOBSJibHxZlMmlE2tqRAZB1DQsvA3kXMSIE6EWLkXwGxNTyEKpM5BVWA8lpk
-----END CERTIFICATE-----"""

# this is generated from the above certificate
new_tlsa = (
    "3 1 1 C156ED202BC70E942AD0D29D038A6828575D4919E1B44794182AF10511492AF1".lower()
)


one_default_node = {
    ("DaneNginx", "66.52.60.249", "proxy"): {"get_agents_state": "DEFAULT"},
    ("DaneNginx", "82.66.5.178", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.97.234", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.142.66", "proxy"): {"get_agents_state": "RUNNING"},
}

one_node_missing = {
    ("DaneNginx", "82.66.5.178", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.97.234", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.142.66", "proxy"): {"get_agents_state": "RUNNING"},
}

one_uncontactable_node = {
    ("DaneNginx", "66.52.60.249", "proxy"): {},
    ("DaneNginx", "82.66.5.178", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.97.234", "proxy"): {"get_agents_state": "RUNNING"},
    ("DaneNginx", "65.108.142.66", "proxy"): {"get_agents_state": "RUNNING"},
}

dns_state = {
    ("DNSDriver", "116.251.187.92", "dns_agent"): {"get_agents_state": "RUNNING"}
}


def return_dns_task(*args, **kwargs):
    f = asyncio.Future()
    # print("ARGS", args)
    # print("KWARGS", kwargs)
    for arg in args:
        if arg[0][0] == "get_agents_state":
            f.set_result(dns_state)
            return f

    for key in list(kwargs):
        # pretty_repr(f"DNS TASKS FOR {key}: {value}")
        if key == "targets":
            f.set_result(
                {("DNSDriver", "116.251.187.92", "dns_agent"): {"sync_object": None}}
            )
            return f

    return f


def return_nginx_task(state, *args, **kwargs):
    f = asyncio.Future()
    # print("ARGS", args)
    # print("KWARGS", kwargs)
    for arg in args:
        if arg[0][0] == "get_agents_state":
            f.set_result(state)
            return f

    certs = {}
    for key, value in kwargs.items():
        # pretty_repr(f"NGINX TASKS FOR {key}: {value}")
        if key == "targets":
            for target, tasks in value.items():
                if ("install_nginx_certs", []) in tasks:
                    certs.update({target: {"install_nginx_certs": new_cert}})
    f.set_result(certs)

    return f


def build_task(task_name, args=[]):
    return task_name, args


def disconnect(*args, **kwargs):
    f = asyncio.Future()
    f.set_result(None)
    return f


@pytest.fixture
def nginx():
    with patch("fluxvault.fluxkeeper.FluxAppManager") as MockClass:
        instance = MockClass.return_value

        instance.build_task.side_effect = build_task
        # instance.run_agents_async.side_effect = return_nginx_task
        instance.disconnect_agent_by_id.side_effect = disconnect
        yield instance


@pytest.fixture
def pdns():
    with patch("fluxvault.fluxkeeper.FluxAppManager") as MockClass:
        instance = MockClass.return_value

        instance.build_task.side_effect = build_task
        instance.run_agents_async.side_effect = return_dns_task
        instance.disconnect_agent_by_id.side_effect = disconnect
        yield instance


@pytest.fixture
def remove_old_tlsa_and_a():
    return [
        call(
            targets={
                ("DNSDriver", "116.251.187.92", "dns_agent"): [
                    (
                        "remove_agents_dns_records",
                        [
                            "testzone.",
                            33443,
                            [
                                "3 1 1 d3a6138edd27b42985bdf20270de8b7c15e149404d11dfaf5bbeaa1767505b92"
                            ],
                            ["66.52.60.249"],
                        ],
                    )
                ]
            }
        )
    ]


@pytest.fixture
def remove_old_tlsa_add_new():
    return [
        call(
            targets={
                ("DNSDriver", "116.251.187.92", "dns_agent"): [
                    (
                        "remove_agents_dns_records",
                        [
                            zone,
                            tls_port,
                            [
                                "3 1 1 d3a6138edd27b42985bdf20270de8b7c15e149404d11dfaf5bbeaa1767505b92"
                            ],
                            [],
                        ],
                    ),
                    (
                        "add_agents_dns_records",
                        [
                            zone,
                            tls_port,
                            [new_tlsa],
                            [],
                        ],
                    ),
                ]
            }
        )
    ]


@pytest.fixture
def dane_already_running(nginx, pdns):
    runner = dane.DaneRunner(nginx, pdns, zone, tls_port)
    runner.first_run = False
    return runner


def test_instantiation(nginx, pdns):
    runner = dane.DaneRunner(nginx, pdns, zone, tls_port)
    assert runner.zone_name == zone
    assert runner.tls_port == tls_port


def test_default_one_node(dane_already_running, remove_old_tlsa_add_new):
    dane_already_running.danenginx.run_agents_async.side_effect = partial(
        return_nginx_task, one_default_node
    )

    asyncio.run(dane_already_running.run_once())

    dane_already_running.dnsdriver.run_agents_async.assert_has_calls(
        remove_old_tlsa_add_new, any_order=True
    )
    # assert record map is what we expect


def test_missing_one_node(dane_already_running, remove_old_tlsa_and_a):
    dane_already_running.danenginx.run_agents_async.side_effect = partial(
        return_nginx_task, one_node_missing
    )

    asyncio.run(dane_already_running.run_once())

    dane_already_running.dnsdriver.run_agents_async.assert_has_calls(
        remove_old_tlsa_and_a, any_order=True
    )


def test_uncontactable_one_node(dane_already_running, remove_old_tlsa_and_a):
    dane_already_running.danenginx.run_agents_async.side_effect = partial(
        return_nginx_task, one_uncontactable_node
    )

    asyncio.run(dane_already_running.run_once())

    assert (
        not remove_old_tlsa_and_a
        in dane_already_running.dnsdriver.run_agents_async.mock_calls
    )

    asyncio.run(dane_already_running.run_once())

    assert (
        not remove_old_tlsa_and_a
        in dane_already_running.dnsdriver.run_agents_async.mock_calls
    )

    asyncio.run(dane_already_running.run_once())

    dane_already_running.dnsdriver.run_agents_async.assert_has_calls(
        remove_old_tlsa_and_a, any_order=True
    )

    # runner = dane_already_running

    # print(pretty_repr(runner.danenginx.run_agents_async.mock_calls))
    # print(pretty_repr(runner.dnsdriver.run_agents_async.mock_calls))

    # print(f"Uncontactable: {pretty_repr(runner.uncontactable_count)}")
    # print(f"Time details: {pretty_repr(runner.time_since_last_sync)}")
    # print(f"all_nginx_nodes: {pretty_repr(runner.all_nginx_nodes)}")
    # print(f"active_nginx_nodes: {pretty_repr(runner.active_nginx_nodes)}")
    # print(f"record_map: {pretty_repr(runner.record_map)}")


# Test cases

# SUT = DaneRunner

# Two main states, first_run and running. This makes a difference because we are using this
# to tell if we need sync the dns state. So we need to test on first run, do we query the dns and
# sync the state. Stub the dns server response and check that the state is parsed correctly

# Running SUT. testing the run_once function.

# Fetch both nginx and dns states
# Determine tasks form those states
# Run tasks
# Sync state from tasks

# Different / Common nginx and dns states
#
# Prior state vs current state
# Probably do up a matrix for this
#
# Prior state all running, Current state one node defaulted
# maybe our app crash? maybe container restarted for whatever reason
# New container replacing a previously removed container. (These actions very
# ulikely to occur in the same run. (1 minute))
#
# Prior state all running, Current state one or more down
# Probably host issues
#
