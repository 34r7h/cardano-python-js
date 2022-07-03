from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

args = sys.argv[1:] or [
    '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"5820f399012098e89f8b0a5eee188258a845a1afdd393ead76084a084345bddedd83"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"5820c09460a12bab651cb3de0dc289727aeaa08b16942a802900cc5bad0b3cdd64ab"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"58202afb6830043e799267e398f90cc0671b28c33060d48d003c4e6a46f60ae64c02"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820ca222f8d530727b20238bab18ab1b1e12018fde41f05ef91944fede95596dc4b"}}}',
    '{"address":"addr1q872eujv4xcuckfarjklttdfep7224gjt7wrxkpu8ve3v6g4x2yx743payyucr327fz0dkdwkj9yc8gemtctgmzpjd8qcdw8qr","outputs":[{"address":"addr1qxx7lc2kyrjp4qf3gkpezp24ugu35em2f5h05apejzzy73c7yf794gk9yzhngdse36rae52c7a6rv5seku25cd8ntves7f5fe4","tokens":[{"unit":"lovelace", "quantity":"3000000"},{"unit":"c4d5ae259e40eb7830df9de67b0a6a536b7e3ed645de2a13eedc7ece7820796f75722065796573","quantity":"1","index":"1","name":"x your eyes"}]}],"submit":"true"}',
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
