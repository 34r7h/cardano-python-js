from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

args = sys.argv[1:] or [
    '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"58202c2066ed218b7c9308526077bcf1e3a0a81a4da99767ce0746093f6e09272e9c"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"58207533eaba8c8636c0a4bc62aeebbe44a9490aea888aca9ebf5123b768b85790ab"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"5820e59e3e2687eb9f77f3c4ab6b08678c0c358b87652e4b7f5a29b4882a17036530"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820d3028f37465a91da25385e6b28eeaa3fc684bb37c2c245ad0ff943991a4d1f33"}}}',
    '{"address":"addr1q9nzv2662ey4kkx96makz82q99wwzehs2uzrt9wwyttq723xkkkcpe0xgfzya3g0jzz825fyfzwm7melppsjr3uw72qs7am8ys","outputs":[{"address":"addr1qxp3rgz76qswp87lg5aegtydh9uxcet00q2h9596wdlykk35hk7hhd6z49vwsylqcl29jq9svvagdjdgt7xy2eakv8vqhzmyes","tokens":[{"index":"0","quantity":"2007747","unit":"lovelace"},{"unit":"ef86d15fdc26f796f22582bdafa4369d13e8cd47ef0480b6f57dc89950616e6a7461726120546f6b656e","quantity":"1","index":"1","name":"Panjtara Token"}]}],"submit":"true"}',
    "mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza",
]
secret = args[0]
data = args[1]
bf = args[2]
dev = False
jsonsecret = json.loads(secret)
jsondata = json.loads(data)

pkey = jsonsecret["payment"]["signing"]["cborHex"]
vkey = jsonsecret["payment"]["verification"]["cborHex"]

network = Network.MAINNET
context = BlockFrostChainContext(bf, network)

sk = PaymentSigningKey.from_cbor(pkey)
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive(jsondata["address"])

# Fuck this builder, I'm going manual bishes
# 1. get all outputs. add-up all fungible tokens. put into output dict.
# 2. get utxos from input address. select utxos with above but closest amounts for fungibles, select utxos holding nfts. add selected as inputs
# 3. 

builder = TransactionBuilder(context)
utxos = context.utxos(str(address))
print("\n\n utxos", utxos, "\n\n")

if len(utxos) == 1:
    builder.add_input(utxos[0])
    # context.utxos = lambda _: utxos[-1:]
else:
    builder.add_input_address(address)
    # builder.add_input(utxos[0]['transaction_id'])
    # builder.add_input(utxos[1])
    # builder.add_input(utxos[2])

    # for x in utxos:
    # print('\nUTXO\n', x, '\n\n')

for x in jsondata["outputs"]:
    # print('\n\n', x, '\n\n')
    outputaddress = x["address"]
    tokens = [2000000]
    # tokens.insert(0, int(0))

    for y in x["tokens"]:
        # print("\n\n", y, "\n\n")
        if y["unit"] == "lovelace":
            tokens[0] = int(y["quantity"])
        else:
            print("\n\n", y["unit"][0:56], y["unit"][-30 : len(y["unit"])], "\n\n")
            policyid = y["unit"][0:56]
            tokennamehex = y["unit"][-30 : len(y["unit"])]
            tokenname = bytes(y["name"], encoding='utf-8')
            print(
                "tokenname",
                tokenname,
                "policyid",
                bytes.fromhex(policyid),
            )
            tokens.append(
                {
                    bytes.fromhex(policyid): {
                        tokenname: int(
                            y["quantity"]
                        )  # Asset name and amount
                    }
                }
            )
    print("\nTokens\n", tokens, "\n\n")
    builder.add_output(
        TransactionOutput(
            Address.from_primitive(outputaddress), Value.from_primitive(tokens)
        )
    )
# print(outputaddress, type(outputaddress), tokens, type(tokens))
if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )
    builder.auxiliary_data = auxiliary_data
    # print('\nMETA\n', auxiliary_data)

unsigned_tx = builder.build(change_address=address)
print("\nINPUTS\n", unsigned_tx.inputs, "\n\n")
print("\nBUILDER\n", builder, "\n\n")
signed_tx = builder.build_and_sign([sk], change_address=address)
tx_id = str(signed_tx.id)
print(signed_tx, tx_id)
# todo remove submit to it's own function
if jsondata["submit"] == "true":
    context.submit_tx(signed_tx.to_cbor())
    print(tx_id)
else:
    # print(builder._fee)
    print(json.dumps([tx_id, signed_tx.to_cbor()]))
