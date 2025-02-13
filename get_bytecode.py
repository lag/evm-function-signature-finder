import requests

print('We need a contract address! (Press enter to use default)')
contract_address = input('Enter contract address: ')

if contract_address == '':
    contract_address = '0x5af0d9827e0c53e4799bb226655a1de152a425a5'


url = "https://ethereum-rpc.publicnode.com"

rpc = {
    "jsonrpc": "2.0",
    "method": "eth_getCode",
    "params": [
        contract_address,
        "latest"
    ],
    "id": 1
}

response = requests.post(url, json=rpc)

print(response.text)
j = response.json()

with open(f"{contract_address}.hex", "w") as f:
    f.write(j["result"][2:])

