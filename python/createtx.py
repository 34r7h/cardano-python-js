from pycardano import (
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    Address,
    TransactionBuilder,
    TransactionOutput,
    Value,
    AuxiliaryData,
    AlonzoMetadata,
    Metadata,
)
import json
import sys

args = sys.argv[1:]
secret = args[0]
data = args[1]
bf = args[2]

jsonsecret = json.loads(secret)
jsondata = json.loads(data)
# print('\n', jsondata, type(jsondata), '\n', bf, '\n')
# print('\n', jsonsecret, type(jsondata), '\n', bf, '\n')

pkey = jsonsecret["payment"]["signing"]["cborHex"]
vkey = jsonsecret["payment"]["verification"]["cborHex"]

network = Network.MAINNET
context = BlockFrostChainContext(bf, network)

sk = PaymentSigningKey.from_cbor(pkey)
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive(jsondata["address"])

builder = TransactionBuilder(context)
builder.add_input_address(address)
utxos = context.utxos(str(address))
# print('\n\n utxos',utxos,'\n\n')

if len(utxos) == 0:
    print("No utxos available on this address")
elif len(utxos) == 1:
    print("add raw input")
    builder.add_input(utxos[0])
else:
    print("use builder\n")

for x in jsondata["outputs"]:
    # print('\n\n', x, '\n\n')
    outputaddress = x["address"]
    tokens = [1000000]
    # tokens.insert(0, int(0))

    for y in x["tokens"]:
        # print("\n\n", y, "\n\n")
        if y["unit"] == "lovelace":
            tokens[0] = int(y["quantity"])
        else:
            print(y["unit"][0 : 56])
            tokens.append(
                {
                    bytes.fromhex(
                        y["unit"][0 : 56]  # Policy ID
                    ): {
                        bytes(y["name"], encoding='utf-8'): int(y["quantity"])  # Asset name and amount
                    }
                }
            )
    print(tokens)
    builder.add_output(
        TransactionOutput(
            Address.from_primitive(outputaddress), Value.from_primitive(tokens)
        )
    )
# print(outputaddress, type(outputaddress), tokens, type(tokens))
if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721:jsondata["metadata"]}))
    )
    builder.auxiliary_data = auxiliary_data
    print(auxiliary_data)

# print(builder)
signed_tx = builder.build_and_sign([sk], change_address=address)
print('keep going')
tx_id = str(signed_tx.id)
# print(signed_tx, tx_id)
# todo remove submit to it's own function
if jsondata["submit"] == 'true':
    context.submit_tx(signed_tx.to_cbor())
print(tx_id, signed_tx)
