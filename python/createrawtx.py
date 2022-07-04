from email import policy
from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

# todo create log module for import to other files
def log(l, d, s):
    dtype = type(d)
    try:
        da = json.dumps(d, indent=2, sort_keys=t) if isinstance(d, dict) else d
    except:
        da = d
    if s:
        print(f"\n\n\n{'─' * 25}\n{l}: {dtype}\n{'─' * 15}\n", da)


t = True
f = False

minfee = 200000
args = sys.argv[1:] or ["{\"payment\":{\"signing\":{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"PaymentSigningKeyShelley_ed25519\",\"cborHex\":\"5820dd80145c03c6dae5b89b3aa336436bc14df9090734a20e028700d57aa2523fe0\"},\"verification\":{\"type\":\"PaymentVerificationKeyShelley_ed25519\",\"description\":\"PaymentVerificationKeyShelley_ed25519\",\"cborHex\":\"5820367c9dd45c3989fb8eda7edfc4b526d01e1a658e4f2704b5f7230c6634a62cc2\"}},\"stake\":{\"signing\":{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"StakeSigningKeyShelley_ed25519\",\"cborHex\":\"5820c6d57797d30cdba281ff3aafcd1314b05cb6779c507763426fb87047b931794b\"},\"verification\":{\"type\":\"StakeVerificationKeyShelley_ed25519\",\"description\":\"StakeVerificationKeyShelley_ed25519\",\"cborHex\":\"58208beeb01cae4d07d9022c1430bfe10a6e2feb4de615ecc881704985ed6d24d418\"}}}","{\"address\":\"addr1q9tpnk7v8twk99au9pfgc78dsahm76r7ht54rc77ycmsnkr2wujhlhyl7dmu3c3kerr9ed8ajsl03jlslfjkak6yxcus564tze\",\"outputs\":[{\"address\":\"addr1qytqt3v9ej3kzefxcy8f59h9atf2knracnj5snkgtaea6p4r8g3mu652945v3gldw7v88dn5lrfudx0un540ak9qt2kqhfjl0d\",\"tokens\":[{\"unit\":\"lovelace\",\"quantity\":\"3461095\",\"index\":\"0\"},{\"unit\":\"06a7f19a3791276f7740068fa2998abc79b20f0411c9541723318b13736c656570696e675f626561757479\",\"quantity\":\"1\",\"index\":\"1\",\"name\":\"sleeping_beauty\"}]}],\"submit\":\"true\"}","mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza"]

secret = args[0]
data = args[1]
bf = args[2]

jsonsecret = json.loads(secret)
jsondata = json.loads(data)

pkey = jsonsecret["payment"]["signing"]["cborHex"]
vkey = jsonsecret["payment"]["verification"]["cborHex"]

network = Network.MAINNET
context = BlockFrostChainContext(bf, network)

sk = PaymentSigningKey.from_cbor(pkey)
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive(jsondata["address"])
alltokens = {}
tokentotals = {}
totallovelaces = 0
outputbyaddress = {}
outputlist = []
leftovers = {}
minlovelaceset = False

for output in jsondata["outputs"]: # Get outputs from api request
    log("output", output, t)
    prepmulti = {} # prepare for multi
    outputbyaddress[output["address"]] = {} # set output address

    # if the only output is lovelace
    if len(output["tokens"]) == 1 and output["tokens"][0]["unit"] == "lovelace":
        log("Only lovelace", "", t)
        minlovelaceset = t
        tokentotals['lovelace'] = {
            "unit": 'lovelace',
            "quantity": int(output["tokens"][0]["quantity"]),
        }
        minlovelaceset = t
        outputlist.append(
            {
                "address": output["address"],
                "lovelace": int(output["tokens"][0]["quantity"]),
            }
        )
    else: # if there's one or more non-lovelace tokens
        for token in output["tokens"]:
            log("Token", token, f)
            if not token["unit"] in tokentotals: # set new token entry to tokentotals 
                log("No token", "", f)
                if token["unit"] == "lovelace":
                    tokentotals[token["unit"]] = {
                        "unit": token["unit"],
                        "quantity": int(token["quantity"]),
                    }
                    minlovelaceset = t
                else:
                    if int(token["quantity"]) > 0:
                        tokentotals[token["unit"][0:56]] = {
                            "unit": token["unit"],
                            "quantity": int(token["quantity"]),
                            "name": str(token["unit"])[56:],
                        }
            else: # increment amount of existing token entry
                if token["unit"] == "lovelace":
                    tokentotals[token["unit"]]["quantity"] += int(token["quantity"])
                    minlovelaceset = t
                else:
                    tokentotals[token["unit"][0:56]]["quantity"] += int(token["quantity"])
            # if len(output["tokens"]) > 1:
            prepmulti[token["unit"]] = int(token["quantity"])
        if len(prepmulti.keys()) > 0:
            log("Prepmulti", prepmulti, t)
            outputlist.append({"address": output["address"], "tokens": prepmulti})
log("outputlist", outputlist, t)

utxos = context.utxos(str(address)) # Get utxos from sending address

sufficientadatxs = []
insufficientadatxs = []
inputsetup = {}

for utxoi, utxo in enumerate(utxos): # Iterate utxos for available lovelace amounts
    log(f"utxo {utxoi}", utxo, t)
    if not "lovelace" in tokentotals: # set lovelace to 1000000 if non-specified in tokentotals
        tokentotals["lovelace"] = {"unit": "lovelace", "quantity": 1000000}
    if utxo.output.amount.coin >= (tokentotals["lovelace"]["quantity"] + minfee): # sufficient amount
        log("amount sufficient", utxo.output.amount.coin, t)
        sufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        sufficientadatxs = sorted(sufficientadatxs, key=lambda d: list(d.keys()))
    else: # insufficient amounts
        log("amount insufficient", utxo.output.amount.coin, t)
        insufficientadatxs.append({str(utxo.output.amount.coin): utxoi})
        insufficientadatxs = sorted(insufficientadatxs, key=lambda d: list(d.keys()), reverse=t)
    if len(utxo.output.amount.multi_asset.keys()) > 0: # if utxo has multiassets
        for tokenpolicy in utxo.output.amount.multi_asset.keys(): # each token's policyid
            alltokens[tokenpolicy.to_primitive().hex()] = { # set dict entry for each multiasset
                "name": list(utxo.output.amount.multi_asset[tokenpolicy].keys())[0],
                "txid": str(utxo.input.transaction_id),
                "txindex": utxo.input.index,
                "tokenqty": utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
                    list(
                        utxo.output.amount.multi_asset[tokenpolicy]
                        .to_primitive()
                        .keys()
                    )[0]
                ],
            }
            log(
                "multi_asset",
                [
                    list(
                        utxo.output.amount.multi_asset[tokenpolicy]
                        .to_primitive()
                        .keys()
                    )[0].hex(),
                    utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
                        list(
                            utxo.output.amount.multi_asset[tokenpolicy]
                            .to_primitive()
                            .keys()
                        )[0]
                    ],
                ],
                f,
            )
            totallovelaces += (utxo.output.amount.coin)
            policykey = str(tokenpolicy)
            if policykey in tokentotals: # check if policykey is requested
                inputsetup[policykey] = { # create input if utxo has requested asset
                    "txid": str(utxo.input.transaction_id),
                    "txindex": utxo.input.index,
                    "tokenqty": utxo.output.amount.multi_asset[
                        tokenpolicy
                    ].to_primitive()[
                        list(
                            utxo.output.amount.multi_asset[tokenpolicy]
                            .to_primitive()
                            .keys()
                        )[0]
                    ],
                }
                # todo incorporate lovelace remainders here
                log('lovelace from multiasset utxo', totallovelaces, t)
                leftovers[policykey] = ( # calculate remaining asset amount to return addr
                    utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
                        list(
                            utxo.output.amount.multi_asset[tokenpolicy]
                            .to_primitive()
                            .keys()
                        )[0]
                    ]
                    - tokentotals[policykey]["quantity"]
                )
            else: # asset is not requested, add full amount to return addr
                leftovers[policykey] = utxo.output.amount.multi_asset[
                    tokenpolicy
                ].to_primitive()[
                    list(
                        utxo.output.amount.multi_asset[tokenpolicy]
                        .to_primitive()
                        .keys()
                    )[0]
                ]
    else: # no assets in utxo
        log('no assets in utxo', '', f)
log("to be leftover", leftovers, t)
log("tokentotals", tokentotals, t)
log("inputsetup", inputsetup, t)
log("sufficientadatxs", sufficientadatxs, t)
log("insufficientadatxs", insufficientadatxs, t)
log("alltokens", alltokens, t)
log("totallovelaces", totallovelaces, t)

if len(sufficientadatxs) > 0: # take ada from first, lowest sufficient utxo
    utxo = dict(sufficientadatxs[0]) # first sufficient utxo
    utxoamount = list(utxo.keys())[0] # amount in utxo
    utxoi = utxo[utxoamount] # index of utxo
    log("First sufficient tx, amount, tx index", [utxo, utxoamount, utxoi], f)

    # calculate difference in lovelace (first sufficient - requested amount)
    min_gte = tokentotals['lovelace']['quantity'] >= 1000000
    utxooutputamount = int(utxos[utxoi].output.amount.coin - 1000000)
    difference = int(utxos[utxoi].output.amount.coin) if min_gte else utxooutputamount - int(tokentotals["lovelace"]["quantity"]) - minfee # difference of requested or min lovelace amount
    inputsetup["lovelace"] = [{ # set input for lovelace in array
        "txid": str(utxos[utxoi].input.transaction_id),
        "txindex": utxos[utxoi].input.index,
        "tokenqty": utxos[utxoi].output.amount.coin,
    }]
else:
    target = 0
    combinedinsufficienttxs = []
    inputsetup["lovelace"] = []
    # todo do the same as lovelace for all tokens
    log("add up insufficients", '', t)
    for insufamount in insufficientadatxs:
        log('insuftally', insufamount, t)
        utxo = dict(insufamount) # first sufficient utxo
        utxoamount = list(utxo.keys())[0] # amount in utxo
        utxoi = utxo[utxoamount] # index of utxo
        if target < tokentotals['lovelace']['quantity']:
            target += int(list(insufamount.keys())[0])
            inputsetup["lovelace"].append({ # set input for lovelace in array
                "txid": str(utxos[utxoi].input.transaction_id),
                "txindex": utxos[utxoi].input.index,
                "tokenqty": utxos[utxoi].output.amount.coin,
            })
            # combinedinsufficienttxs.append(insufamount)
        else: 
            log('target met', target, f)
    log('target', target, t)
    log('inputsetup["lovelace"]', inputsetup["lovelace"], t)
    difference = target - int(tokentotals["lovelace"]["quantity"]) - minfee
    # for combinedinsufficienttxs

txins = []
log("difference", difference, t)
log("tokentotals, inputsetup", [tokentotals, inputsetup], t)

for tkey in tokentotals.keys():
    usedutxos = {}
    if not tkey == "lovelace" and tkey in inputsetup:
        id = inputsetup[tkey]["txid"]
        index = inputsetup[tkey]["txindex"]
        # log('utxo with token', utxos[index], t)
        txinlist = TransactionInput.from_primitive([id, index])
        txins.append(txinlist)
        usedutxos[id+'-'+str(index)] = {'id': str(id), 'index': str(index)}
for tx in inputsetup['lovelace']:
    log("tx", tx, t)
    log('test used', not (tx['txid'] + '-' + str(tx['txindex'])) in usedutxos, t)
    if not (tx['txid'] + '-' + str(tx['txindex'])) in usedutxos:
        txins.append(TransactionInput.from_primitive([tx['txid'], tx['txindex']]))
log("txins", txins, t)

addr = address
log("addr", addr, t)
log("usedutxos", usedutxos, t)

txouts = []

for output in outputlist:
    if not "tokens" in output:
        txouts.append(
            TransactionOutput(Address.decode(output["address"]), output["lovelace"])
        )
    else:
        multi = [1000000, {}]
        for tokenkey, tokenamount in output["tokens"].items():
            if tokenkey == "lovelace":
                multi[0] = tokenamount
            else:
                log("tokenkey", tokenkey, f)
                policy_id = bytes.fromhex(tokenkey[0:56])
                token_name = bytes.fromhex(tokenkey[56:])
                multi[1][policy_id] = {token_name: tokenamount}
        txouts.append(
            TransactionOutput(
                Address.decode(output["address"]), Value.from_primitive(multi)
            )
        )

# change
# TODO tally leftovers of all tokens and send back to sender. Set minlovelaceset = True or figure out where the missing lovelace is.
changemulti = [difference]
for policykey, qty in leftovers.items():
    policy_id = bytes.fromhex(policykey)
    token_name = alltokens[policykey]["name"].to_primitive()
    if qty > 0:
        if len(changemulti) == 1:
            changemulti.append({})
        changemulti[1][policy_id] = {token_name: qty}
log(f"changemulti", changemulti, t)
txouts.append(TransactionOutput(addr, Value.from_primitive(changemulti)))

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

# TODO add and test metadata
for inp in txins:
        log(f"txin", inp, t)
for out in txouts:
        log(f"txout", out, t)
tx_body = TransactionBody(inputs=txins, outputs=txouts, fee=minfee)
log("tx_body", tx_body, f)

signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

tx_id = str(signed_tx.id)

log("signed_tx and id", [signed_tx, tx_id], f)
log("############### Submitting transaction ###############", "", t)

context.submit_tx(signed_tx.to_cbor())
