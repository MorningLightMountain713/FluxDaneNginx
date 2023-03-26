import pickle

from rich.pretty import pprint

with open(".dane_tlsa_address_mapping", "rb") as f:
    data = pickle.load(f)
    pprint(data)

# for server, items in data.items():
#     del items["a"][('DaneNginx', '127.0.0.1', 'proxy')]
#     del items["tlsa"][('DaneNginx', '127.0.0.1', 'proxy')]


# with open(".dane_tlsa_address_mapping", "wb") as f:
#     pickle.dump(data, f)
