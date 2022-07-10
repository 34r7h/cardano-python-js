from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

args = sys.argv[1:] or ["{\"payment\":{\"signing\":{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"PaymentSigningKeyShelley_ed25519\",\"cborHex\":\"5820d62379993894309c41ff5179df7db1431cf5b723bbee3cd77de9258df052ea95\"},\"verification\":{\"type\":\"PaymentVerificationKeyShelley_ed25519\",\"description\":\"PaymentVerificationKeyShelley_ed25519\",\"cborHex\":\"58206d0c8ef76c29b1bddc863003d07e99865831a96ad2c4db3a02e60bb417e6521c\"}},\"stake\":{\"signing\":{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"StakeSigningKeyShelley_ed25519\",\"cborHex\":\"5820e417df710ab747ca7e072c52c19104921cc3e0f487e40eae1d88d5df770b54eb\"},\"verification\":{\"type\":\"StakeVerificationKeyShelley_ed25519\",\"description\":\"StakeVerificationKeyShelley_ed25519\",\"cborHex\":\"582039827ab0c96922a7f7e685beee4ca839302f4fe946fb38d3466b4140f9985b95\"}}}","{\"address\":\"addr1qxeky720e3yx5vfszs4ssk6tdlnhvdnngevr0qgu6q39xw0z7wxgc8snm7m5ce69fdtkuddmugwl6z2zev29f85rk2wq0mmf0q\",\"outputs\":[{\"address\":\"addr1q82se2jhz67vfex09538sddyhr2eyluts4lg0ntvy2exg525ttf89d5ppwpjnpyq2tly0gj8tz8qr2z05nw69kyjp9hsnmaux6\",\"tokens\":[{\"index\":\"0\",\"quantity\":\"2000000\",\"unit\":\"lovelace\"}]},{\"address\":\"addr1q9kf8n2n72tnru4jyc9qvjvz7c5jwtpzqag2uwsfymv9w0ftfdq8r3z5yfvrec346hlulvsalyy5up8wzng8fch7srdscx8ecv\",\"tokens\":[{\"index\":\"0\",\"quantity\":\"2000053\",\"unit\":\"lovelace\"}]}],\"submit\":\"false\"}","mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza"]
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
