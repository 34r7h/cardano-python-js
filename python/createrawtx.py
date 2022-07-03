from email import policy
from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

minfee = 200000
args = sys.argv[1:] or [
    '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"5820f399012098e89f8b0a5eee188258a845a1afdd393ead76084a084345bddedd83"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"5820c09460a12bab651cb3de0dc289727aeaa08b16942a802900cc5bad0b3cdd64ab"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"58202afb6830043e799267e398f90cc0671b28c33060d48d003c4e6a46f60ae64c02"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820ca222f8d530727b20238bab18ab1b1e12018fde41f05ef91944fede95596dc4b"}}}',
    '{"address":"addr1q872eujv4xcuckfarjklttdfep7224gjt7wrxkpu8ve3v6g4x2yx743payyucr327fz0dkdwkj9yc8gemtctgmzpjd8qcdw8qr","outputs":[               {"address":"addr1qxx7lc2kyrjp4qf3gkpezp24ugu35em2f5h05apejzzy73c7yf794gk9yzhngdse36rae52c7a6rv5seku25cd8ntves7f5fe4","tokens":[{"unit":"lovelace", "quantity":"3000000"},{"unit":"c4d5ae259e40eb7830df9de67b0a6a536b7e3ed645de2a13eedc7ece7820796f75722065796573","quantity":"1","index":"1","name":"x your eyes"}]},{"address":"addr1qytqt3v9ej3kzefxcy8f59h9atf2knracnj5snkgtaea6p4r8g3mu652945v3gldw7v88dn5lrfudx0un540ak9qt2kqhfjl0d","tokens":[{"unit":"lovelace", "quantity":"1200000"}]}],"submit":"true"}',
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

tokentotals = {}
outputbyaddress = {}
outputlist = []
leftovers = {}

for output in jsondata["outputs"]:
    prepmulti = {}
    print(
        f"\n\n\n{'─' * 25}\nOutput:\n{'─' * 15}\n",
        json.dumps(output, indent=2, sort_keys=True),
    )

    outputbyaddress[output["address"]] = {}
    if len(output["tokens"]) == 1 and output["tokens"][0]["unit"] == "lovelace":
        outputlist.append(
            {
                "address": output["address"],
                "lovelace": int(output["tokens"][0]["quantity"]),
            }
        )
    for token in output["tokens"]:
        print(
            f"\n\n\n{'─' * 25}\nToken:\n{'─' * 15}\n",
            json.dumps(token, indent=2, sort_keys=True),
        )

        if not token["unit"] in tokentotals:
            print("no token")
            if token["unit"] == "lovelace":
                tokentotals[token["unit"]] = {
                    "unit": token["unit"],
                    "quantity": int(token["quantity"]),
                }
            else:
                tokentotals[token["unit"][0:56]] = {
                    "unit": token["unit"],
                    "quantity": int(token["quantity"]),
                    "name": str(token["unit"])[56:],
                }
        else:
            if token["unit"] == "lovelace":
                tokentotals[token["unit"]]["quantity"] += int(token["quantity"])
            else:
                tokentotals[token["unit"][0:56]]["quantity"] += int(token["quantity"])
        if len(output["tokens"]) > 1:
            prepmulti[token["unit"]] = int(token["quantity"])
    if len(prepmulti.keys()) > 0:
        print(
            f"\n\n\n{'─' * 25}\nPrepmulti:\n{'─' * 15}\n",
            json.dumps(prepmulti, indent=2, sort_keys=True),
        )
        outputlist.append({"address": output["address"], "tokens": prepmulti})

print(
    f"\n\n\n{'─' * 25}\noutputlist:\n{'─' * 15}\n",
    json.dumps(outputlist, indent=2, sort_keys=True),
)
utxos = context.utxos(str(address))

sufficientadatxs = []
insufficientadatxs = []
inputsetup = {}
for utxoi, utxo in enumerate(utxos):
    print(f"\n\n\n{'─' * 25}\nutxo:{utxoi}\n{'─' * 15}\n", utxo)

    if utxo.output.amount.coin >= (tokentotals["lovelace"]["quantity"] + minfee):
        print(
            f"\n\n\n{'─' * 25}\namount sufficient:\n{'─' * 15}\n",
            utxo.output.amount.coin,
        )
        sufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        sufficientadatxs = sorted(sufficientadatxs, key=lambda d: list(d.keys()))
    else:
        print(
            f"\n\n\n{'─' * 25}\namount insufficient:\n{'─' * 15}\n",
            utxo.output.amount.coin,
        )
        insufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        insufficientadatxs = sorted(insufficientadatxs, key=lambda d: list(d.keys()))
    if len(utxo.output.amount.multi_asset.keys()) > 0:
        print(
            f"\n\n\n{'─' * 25}\nmulti_asset:\n{'─' * 15}\n",
            list(utxo.output.amount.multi_asset.to_primitive().keys())[0].hex(),
            utxo.output.amount.multi_asset.to_primitive()[
                list(utxo.output.amount.multi_asset.to_primitive().keys())[0]
            ],
        )

        policykey = list(utxo.output.amount.multi_asset.to_primitive().keys())[0].hex()
        inputsetup[policykey] = {
            "txid": str(utxo.input.transaction_id),
            "txindex": utxo.input.index,
            "tokenqty": utxo.output.amount.multi_asset.to_primitive()[
                list(utxo.output.amount.multi_asset.to_primitive().keys())[0]
            ][bytes.fromhex(tokentotals[policykey]["name"])],
            "tokenname": bytes.fromhex(tokentotals[policykey]["name"]),
        }

print(
    f"\n\n\n{'─' * 25}\ntokentotals:\n{'─' * 15}\n",
    json.dumps(tokentotals, indent=2, sort_keys=True),
)
print(f"\n\n\n{'─' * 25}\ninputsetup:\n{'─' * 15}\n", inputsetup)

print("\nsufficientadatxs\n", json.dumps(sufficientadatxs, indent=2, sort_keys=True))
print(
    "\ninsufficientadatxs:\n", json.dumps(insufficientadatxs, indent=2, sort_keys=True)
)

if len(sufficientadatxs) > 0:
    utxo = dict(sufficientadatxs[0])
    print("\nFirst sufficient tx:", utxo)
    # First sufficient tx: {'5639430': 2}
    utxoamount = list(utxo.keys())[0]
    print("\nAmount in first sufficient tx:", utxoamount)
    # Amount in first sufficient tx: 5639430
    utxoi = utxo[utxoamount]
    print("\nFirst sufficient tx, amount, tx index:\n", utxo, utxoamount, utxoi)
    # First sufficient tx, amount, tx index: {'5639430': 2} 5639430 2
    difference = (
        int(utxos[utxoi].output.amount.coin)
        - int(tokentotals["lovelace"]["quantity"])
        - minfee
    )
    inputsetup["lovelace"] = {
        "txid": str(utxos[utxoi].input.transaction_id),
        "txindex": utxos[utxoi].input.index,
        "tokenqty": utxos[utxoi].output.amount.coin,
    }
else:
    # todo
    print("\nadd up insufficients\n")

print("\nDifference:", difference)

txins = []

for tkey in tokentotals.keys():
    id = inputsetup[tkey]["txid"]
    index = inputsetup[tkey]["txindex"]
    txinlist = TransactionInput.from_primitive([id, index])
    txins.append(txinlist)

print(f"\n\n\n{'─' * 25}\ntxins:\n{'─' * 15}\n", txins)

addr = address

print("\nAddr:", addr)

txouts = []

for output in outputlist:
    if not "tokens" in output:
        txouts.append(
            TransactionOutput(Address.decode(output["address"]), output["lovelace"])
        )
    else:
        multi = [2000000, {}]
        for tokenkey, tokenamount in output["tokens"].items():
            if tokenkey == "lovelace":
                multi[0] = tokenamount
            else:
                print(tokenkey)
                policy_id = bytes.fromhex(tokenkey[0:56])
                token_name = bytes.fromhex(tokenkey[56:])
                multi[1][policy_id] = {token_name: tokenamount}
        txouts.append(TransactionOutput(Address.decode(output["address"]), Value.from_primitive(multi)))

print(f"\n\n\n{'─' * 25}\ntxouts:\n{'─' * 15}\n", txouts)

# change
txouts.append(TransactionOutput(addr, difference+1379280))

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

# TODO add and test metadata

tx_body = TransactionBody(inputs=txins, outputs=txouts, fee=minfee)

print(f"\n\n\n{'─' * 25}\ntx_body and tx fee:\n{'─' * 15}\n", tx_body, tx_body.fee)

signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

tx_id = str(signed_tx.id)

print("\nSigned tx, tx id:\n", signed_tx, tx_id)
print("############### Submitting transaction ###############")

context.submit_tx(signed_tx.to_cbor())
