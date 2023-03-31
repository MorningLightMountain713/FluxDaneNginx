from pathlib import Path
import pickle

record_map_path = Path(".dane_tlsa_address_mapping")


def pytest_configure(config):
    record_map = {
        ("DNSDriver", "116.251.187.92", "dns_agent"): {
            "a": {
                ("DaneNginx", "65.108.142.66", "proxy"): "65.108.142.66",
                ("DaneNginx", "66.52.60.249", "proxy"): "66.52.60.249",
                ("DaneNginx", "65.108.97.234", "proxy"): "65.108.97.234",
                ("DaneNginx", "82.66.5.178", "proxy"): "82.66.5.178",
            },
            "tlsa": {
                (
                    "DaneNginx",
                    "65.108.142.66",
                    "proxy",
                ): "3 1 1 5cdc10ca73d252711f4c734a8eb7a2f2c218b0409d752bb486cd468ba7d86b1b",
                (
                    "DaneNginx",
                    "66.52.60.249",
                    "proxy",
                ): "3 1 1 d3a6138edd27b42985bdf20270de8b7c15e149404d11dfaf5bbeaa1767505b92",
                (
                    "DaneNginx",
                    "65.108.97.234",
                    "proxy",
                ): "3 1 1 c3e813a853e8bf84c4892642ad8c44216e5a43dfc02e38cd9ba5df9506f5cba8",
                (
                    "DaneNginx",
                    "82.66.5.178",
                    "proxy",
                ): "3 1 1 8271e6273bc46f7f796ed3ce142d7b0085d8c9205e67a8a54f75a72e99d7c7c1",
            },
        }
    }
    with open(record_map_path, "wb") as stream:
        pickle.dump(record_map, stream)


def pytest_unconfigure(config):
    record_map_path.unlink()
