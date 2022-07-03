from email import policy
from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

# todo create log module for import to other files
def log(l, d, s):
    dtype = type(d)
    da = json.dumps(d, indent=2, sort_keys=t) if isinstance(d, dict) else d
    if s:
        print(f"\n\n\n{'─' * 25}\n{l}: {dtype}\n{'─' * 15}\n", da)
t = True
f = False

minfee = 200000
args = sys.argv[1:] or ["{\"payment\":{\"signing\":{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"PaymentSigningKeyShelley_ed25519\",\"cborHex\":\"5820d62379993894309c41ff5179df7db1431cf5b723bbee3cd77de9258df052ea95\"},\"verification\":{\"type\":\"PaymentVerificationKeyShelley_ed25519\",\"description\":\"PaymentVerificationKeyShelley_ed25519\",\"cborHex\":\"58206d0c8ef76c29b1bddc863003d07e99865831a96ad2c4db3a02e60bb417e6521c\"}},\"stake\":{\"signing\":{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"StakeSigningKeyShelley_ed25519\",\"cborHex\":\"5820e417df710ab747ca7e072c52c19104921cc3e0f487e40eae1d88d5df770b54eb\"},\"verification\":{\"type\":\"StakeVerificationKeyShelley_ed25519\",\"description\":\"StakeVerificationKeyShelley_ed25519\",\"cborHex\":\"582039827ab0c96922a7f7e685beee4ca839302f4fe946fb38d3466b4140f9985b95\"}}}","{\"address\":\"addr1qxeky720e3yx5vfszs4ssk6tdlnhvdnngevr0qgu6q39xw0z7wxgc8snm7m5ce69fdtkuddmugwl6z2zev29f85rk2wq0mmf0q\",\"outputs\":[{\"address\":\"addr1qytqt3v9ej3kzefxcy8f59h9atf2knracnj5snkgtaea6p4r8g3mu652945v3gldw7v88dn5lrfudx0un540ak9qt2kqhfjl0d\",\"tokens\":[{\"unit\":\"92952ee27042c68cd5a807d686dd75010115dfe6feab2c898f0fde1458796d626f6c\",\"quantity\":\"27\",\"index\":\"2\"}]}],\"submit\":\"true\"}","mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza"]

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
minlovelaceset = False

for output in jsondata["outputs"]:
    log('output', output, t)
    prepmulti = {}
    outputbyaddress[output["address"]] = {}
    if len(output["tokens"]) == 1 and output["tokens"][0]["unit"] == "lovelace":
        log('Only lovelace', '', t)
        minlovelaceset = t
        outputlist.append(
            {
                "address": output["address"],
                "lovelace": int(output["tokens"][0]["quantity"]),
            }
        )
    for token in output["tokens"]:
        log('Token', token, t)
        if not token["unit"] in tokentotals:
            log('No token', '', t)
            if token["unit"] == "lovelace":
                tokentotals[token["unit"]] = {
                    "unit": token["unit"],
                    "quantity": int(token["quantity"]),
                }
                minlovelaceset = t
            else:
                tokentotals[token["unit"][0:56]] = {
                    "unit": token["unit"],
                    "quantity": int(token["quantity"]),
                    "name": str(token["unit"])[56:],
                }
        else:
            if token["unit"] == "lovelace":
                tokentotals[token["unit"]]["quantity"] += int(token["quantity"])
                minlovelaceset = t
            else:
                tokentotals[token["unit"][0:56]]["quantity"] += int(token["quantity"])
        # if len(output["tokens"]) > 1:
        prepmulti[token["unit"]] = int(token["quantity"])
    if len(prepmulti.keys()) > 0:
        log('Prepmulti', prepmulti, t)
        outputlist.append({"address": output["address"], "tokens": prepmulti})
log('outputlist', outputlist, t)

utxos = context.utxos(str(address))

sufficientadatxs = []
insufficientadatxs = []
inputsetup = {}
for utxoi, utxo in enumerate(utxos):
    log(f'utxo {utxoi}', utxo, t)
    if not 'lovelace' in tokentotals:
        tokentotals["lovelace"] = {
            'unit': 'lovelace',
            'quantity': 0
        }
    if utxo.output.amount.coin >= (tokentotals["lovelace"]["quantity"] + minfee):
        log('amount sufficient', utxo.output.amount.coin, t)

        sufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        sufficientadatxs = sorted(sufficientadatxs, key=lambda d: list(d.keys()))
    else:
        log('amount insufficient', utxo.output.amount.coin, t)

        insufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        insufficientadatxs = sorted(insufficientadatxs, key=lambda d: list(d.keys()))
    if len(utxo.output.amount.multi_asset.keys()) > 0:
        for tokenpolicy in utxo.output.amount.multi_asset.keys():
            log('tokenpolicy', tokenpolicy, t)
            log(
                'multi_asset', 
                [
                    list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[0].hex(),
                    utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
                    list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[0]
                ]], t)
            log('policy fix', list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[0].hex(), t)

            policykey = str(tokenpolicy)
            log('policykey from utxo', policykey, t)
            # log('policykey in  tokentotals', [policykey, tokentotals], t)

            if policykey in tokentotals:
                log('policykey in tokentotals', list(utxo.output.amount.multi_asset[tokenpolicy]), t)
                inputsetup[policykey] = {
                    "txid": str(utxo.input.transaction_id),
                    "txindex": utxo.input.index,
                    "tokenqty": utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
                        list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[0]
                    ]
                }
log('tokentotals', tokentotals, t)
log('inputsetup', inputsetup, t)
log('sufficientadatxs', sufficientadatxs, t)
log('insufficientadatxs', insufficientadatxs, t)

if len(sufficientadatxs) > 0:
    utxo = dict(sufficientadatxs[0])
    utxoamount = list(utxo.keys())[0]
    utxoi = utxo[utxoamount]
    log('First sufficient tx, amount, tx index', [utxo, utxoamount, utxoi], t)

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
    log('add up insufficients', '', t)

log('difference', difference, t)

txins = []

log('difference', difference, t)
log('tokentotals, inputsetup', [tokentotals, inputsetup], t)

for tkey in tokentotals.keys():
    log('tkey', tkey, t)
    if not tkey == 'lovelace' and tkey in inputsetup:
        id = inputsetup[tkey]["txid"]
        index = inputsetup[tkey]["txindex"]
        # log('utxo with token', utxos[index], t)
        txinlist = TransactionInput.from_primitive([id, index])
        txins.append(txinlist)
log('txins', txins, t)

addr = address
log('addr', addr, t)

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
                log('tokenkey', tokenkey, t)
                policy_id = bytes.fromhex(tokenkey[0:56])
                token_name = bytes.fromhex(tokenkey[56:])
                multi[1][policy_id] = {token_name: tokenamount}
        txouts.append(TransactionOutput(Address.decode(output["address"]), Value.from_primitive(multi)))
log('txouts', txouts, t)

# change
# TODO tally leftovers of all tokens and send back to sender. Set minlovelaceset = True or figure out where the missing lovelace is.
txouts.append(TransactionOutput(addr, difference+1379280))

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

# TODO add and test metadata

tx_body = TransactionBody(inputs=txins, outputs=txouts, fee=minfee)
log('tx_body', tx_body, t)

signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

tx_id = str(signed_tx.id)

log('signed_tx and id', [signed_tx, tx_id], t)
log('############### Submitting transaction ###############', '', t)

context.submit_tx(signed_tx.to_cbor())
