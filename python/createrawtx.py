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
        print(f"\n\n\n{'─' * 25}\n{l}: {dtype}\n{'─' * 15}\n")
        if type(da) == list or type(da) == set:
            for xi, x in enumerate(da):
                print(f"{xi}:", x, "\n")
        else:
            print(da)


t = True
f = False

args = sys.argv[1:] or [
    '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"5820d5eab6c1c4986a39a230537e8a6eb11f49dbb8a7bd8e368967eb84bebfb7e488"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"582086d38b30b6a2b42dd1258f8c7ce3e26096776f898d41f5dbb4c70277fd3bb4ec"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"58208fd907a4b148843e7a091cfc6b55231b0ce9287bda9c3dbd8b5edb98c9ea4163"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820b99ba95ad8f4856d1c003456473c3189362c7d2d879f98d9b0cd755637a41e2e"}}}',
    '{"address":"addr1qytqt3v9ej3kzefxcy8f59h9atf2knracnj5snkgtaea6p4r8g3mu652945v3gldw7v88dn5lrfudx0un540ak9qt2kqhfjl0d","outputs":[{"address":"addr1q9tpnk7v8twk99au9pfgc78dsahm76r7ht54rc77ycmsnkr2wujhlhyl7dmu3c3kerr9ed8ajsl03jlslfjkak6yxcus564tze","tokens":[{"unit":"lovelace","quantity":"3188158","index":"0"},{"unit":"92952ee27042c68cd5a807d686dd75010115dfe6feab2c898f0fde1458796d626f6c","quantity":"1","index":"1"}]},{"address":"addr1q872eujv4xcuckfarjklttdfep7224gjt7wrxkpu8ve3v6g4x2yx743payyucr327fz0dkdwkj9yc8gemtctgmzpjd8qcdw8qr","tokens":[{"unit":"lovelace","quantity":"2900000","index":"0"},{"unit":"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d61","quantity":"1","index":"2","name":"a"}]}],"submit":"true"}',
    "mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza",
]

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
addr = address


# Fetch utxo data
utxos_from_bf = context.utxos(str(address))
# TODO: allow multiple inputs

# Instantiate structs and values
alltokens = {}
inputsetup = {}
insufficientadatxs = []
insufficienttxs = {"lovelace": []}
insufficient_sorted = {}
leftovers = {}
outputbyaddress = {}
outputlist = []
minfee = 200000
minlovelaceset = False
return_tokens = {}
sufficientadatxs = []
sufficienttxs = {"lovelace": []}
sufficient_sorted = {}
tokens = {}
tokentotals = {}
total_tokens_requested = {
    'lovelace': minfee
}
total_lovelace_from_inputs = 0
tx_inputs = []
tx_outputs = []
usedutxos = set()
utxos = {}

for output in jsondata["outputs"]:  # Get outputs from api request
    log("output", output, f)
    prepmulti = {}  # prepare for multi
    outputbyaddress[output["address"]] = {}  # set output address
    for token in output["tokens"]:
        outputbyaddress[output["address"]][token["unit"]] = token["quantity"]
        if token["unit"] in total_tokens_requested:
            total_tokens_requested[token["unit"]] += int(token["quantity"])
        else:
            total_tokens_requested[token["unit"]] = int(token["quantity"])

for utxoindex, utxo in enumerate(utxos_from_bf):
    log("utxo:" + str(utxoindex), utxo, f)
    tx_id = str(utxo.input.transaction_id)
    coin = utxo.output.amount.coin
    index = utxo.input.index
    utxos[tx_id] = {"lovelaces": utxo.output.amount.coin, "tokens": {}, "index": index}
    if coin >= total_tokens_requested["lovelace"]:
        sufficienttxs["lovelace"].append({str(coin): tx_id})
    else:
        insufficienttxs["lovelace"].append({str(coin): tx_id})
    if len(utxo.output.amount.multi_asset.keys()) > 0:
        for tokenkey in utxo.output.amount.multi_asset.keys():
            policy_id = tokenkey.to_primitive().hex()
            b_name = list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
            hex_name = (
                list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
                .to_primitive()
                .hex()
            )
            utxos[tx_id]["tokens"][policy_id] = {
                "amount": utxo.output.amount.multi_asset[tokenkey][b_name],
                "b_name": b_name,
                "hex_name": hex_name,
                "policy_id": policy_id,
                "policy_script": tokenkey,
            }
            tokens[policy_id + hex_name] = utxos[tx_id]["tokens"][policy_id]

            token = utxos[tx_id]["tokens"][policy_id]
            if token["amount"] >= total_tokens_requested[policy_id + hex_name]:
                if not policy_id + hex_name in sufficienttxs:
                    sufficienttxs[policy_id + hex_name] = [
                        {str(token["amount"]): tx_id}
                    ]
                else:
                    sufficienttxs[policy_id + hex_name].append(
                        {str(token["amount"]): tx_id}
                    )
            else:
                if not policy_id + hex_name in insufficienttxs:
                    insufficienttxs[policy_id + hex_name] = [
                        {str(token["amount"]): tx_id}
                    ]
                else:
                    insufficienttxs[policy_id + hex_name].append(
                        {str(token["amount"]): tx_id}
                    )

# Create Inputs (TransactionInput.from_primitive([id, index]))
# Calculate return change

for token, amount in total_tokens_requested.items():
    log("sufficienttxs[token]", sufficienttxs[token], f)
    if token in sufficienttxs:
        log("token sufficient", token, f)
        sufficient_sorted[token] = sorted(sufficienttxs[token], key=lambda d: d.keys())
        if len(sufficient_sorted[token]) > 0:
            id = sufficient_sorted[token][0][str(amount)]
            log("sufficient_sorted[token][0]", id, f)
            if not id in usedutxos:
                tx_inputs.append(
                    TransactionInput.from_primitive([id, utxos[id]["index"]])
                )
                usedutxos.add(id)
    if token in insufficienttxs:
        log("token insufficient", token, f)
        insufficient_sorted[token] = sorted(
            insufficienttxs[token], key=lambda d: d.keys(), reverse=t
        )
        target = 0
        for partial in insufficient_sorted[token]:
            partial_tuple = list(partial.items())[0]
            partial_amount = partial_tuple[0]
            partial_id = partial_tuple[1]
            target += int(partial_amount)
            usedutxos.add(partial_id)
            tx_inputs.append(
                TransactionInput.from_primitive(
                    [partial_id, utxos[partial_id]["index"]]
                )
            )
            log("target", target, f)
            if target > int(amount):
                return_tokens[token] = target - int(amount)
                break

outputbyaddress[str(address)] = return_tokens
for address, output in outputbyaddress.items():
    log(address, output, t)
    if len(output.keys()) > 1:
        multi = {}
        for policy_id, amount in output.items():
            if not policy_id == "lovelace":
                log(policy_id, amount, t)
                multi[tokens[policy_id]["policy_script"].to_primitive()] = {
                    tokens[policy_id]["b_name"].to_primitive(): int(amount)
                }
                log("multi", multi, t)
        tx_outputs.append(
            TransactionOutput(
                Address.decode(address),
                Value.from_primitive([int(output["lovelace"]), multi]),
            )
        )
    else:
        tx_outputs.append(
            TransactionOutput(
                Address.decode(address), Value.from_primitive([int(output["lovelace"])])
            )
        )

        # multi = [output['lovelace'], ]
# Create Outputs (
#   multi = [1000000, {}],
#   multi[1][policy_id] = {token_name: tokenamount}
#   TransactionOutput(
#       Address.decode(output["address"]),
#       Value.from_primitive(multi)
#   )
# )


log("utxos_from_bf", utxos_from_bf, t)
log("utxos", utxos, t)
log("outputbyaddress", outputbyaddress, t)
log("total_tokens_requested", total_tokens_requested, t)
log("sufficienttxs", sufficienttxs, t)
log("insufficienttxs", insufficienttxs, t)
log("usedutxos", usedutxos, t)
log("return_tokens", return_tokens, t)
log("tokens", tokens, t)
log("tx_inputs", tx_inputs, t)
log("tx_outputs", tx_outputs, t)

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

# # if the only output is lovelace
# if len(output["tokens"]) == 1 and output["tokens"][0]["unit"] == "lovelace":
#     log("Only lovelace", "", t)
#     minlovelaceset = t
#     tokentotals["lovelace"] = {
#         "unit": "lovelace",
#         "quantity": int(output["tokens"][0]["quantity"]),
#     }
#     minlovelaceset = t
#     outputlist.append(
#         {
#             "address": output["address"],
#             "lovelace": int(output["tokens"][0]["quantity"]),
#         }
#     )
# else:  # if there's one or more non-lovelace tokens
#     for token in output["tokens"]:
#         log("Token", token, f)
#         if not token["unit"] in tokentotals:  # set new token entry to tokentotals
#             log("No token", "", f)
#             if token["unit"] == "lovelace":
#                 tokentotals[token["unit"]] = {
#                     "unit": token["unit"],
#                     "quantity": int(token["quantity"]),
#                 }
#                 minlovelaceset = t
#             else:
#                 if int(token["quantity"]) > 0:
#                     tokentotals[token["unit"][0:56]] = {
#                         "unit": token["unit"],
#                         "quantity": int(token["quantity"]),
#                         "name": str(token["unit"])[56:],
#                     }
#         else:  # increment amount of existing token entry
#             if token["unit"] == "lovelace":
#                 tokentotals[token["unit"]]["quantity"] += int(token["quantity"])
#                 minlovelaceset = t
#             else:
#                 tokentotals[token["unit"][0:56]]["quantity"] += int(token["quantity"])
#         # if len(output["tokens"]) > 1:
#         prepmulti[token["unit"]] = int(token["quantity"])
#     if len(prepmulti.keys()) > 0:
#         log("Prepmulti", prepmulti, f)
#         outputlist.append({"address": output["address"], "tokens": prepmulti})
# log("outputlist", outputlist, f)


# for utxoi, utxo in enumerate(utxos):  # Iterate utxos for available lovelace amounts
#     log(f"utxo {utxoi}", utxo, f)
#     # totallovelaces += utxo.output.amount.coin
#     # if len(utxo.output.amount.multi_asset.keys()) > 0:  # if utxo has multiassets
#     for tokenpolicy in utxo.output.amount.multi_asset.keys():  # each token's policyid

#         alltokens[
#             tokenpolicy.to_primitive().hex()
#         ] = {  # set dict entry for each multiasset
#             "name": list(utxo.output.amount.multi_asset[tokenpolicy].keys())[0],
#             "txid": str(utxo.input.transaction_id),
#             "txindex": utxo.input.index,
#             "tokenqty": utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
#                 list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[
#                     0
#                 ]
#             ],
#         }

#         policykey = str(tokenpolicy)
#         if (
#             policykey in tokentotals and not str(utxo.input.transaction_id) in usedutxos
#         ):  # check if policykey is requested
#             inputsetup[policykey] = {  # create input if utxo has requested asset
#                 "txid": str(utxo.input.transaction_id),
#                 "txindex": utxo.input.index,
#                 "tokenqty": utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
#                     list(
#                         utxo.output.amount.multi_asset[tokenpolicy]
#                         .to_primitive()
#                         .keys()
#                     )[0]
#                 ],
#                 "lovelaces": utxo.output.amount.coin,
#             }
#             usedutxos.add(str(utxo.input.transaction_id))
#             # todo incorporate lovelace remainders here

#             leftovers[policykey] = (  # calculate remaining asset amount to return addr
#                 utxo.output.amount.multi_asset[tokenpolicy].to_primitive()[
#                     list(
#                         utxo.output.amount.multi_asset[tokenpolicy]
#                         .to_primitive()
#                         .keys()
#                     )[0]
#                 ]
#                 - tokentotals[policykey]["quantity"]
#             )
#         else:  # asset is not requested, add full amount to return addr
#             leftovers[policykey] = utxo.output.amount.multi_asset[
#                 tokenpolicy
#             ].to_primitive()[
#                 list(utxo.output.amount.multi_asset[tokenpolicy].to_primitive().keys())[
#                     0
#                 ]
#             ]


# log("leftover assets", leftovers, t)
# log("alltokens", alltokens, t)


# txins = []
# # log("difference", difference, t)
# log("tokentotals", tokentotals, t)
# log("inputsetup", inputsetup, t)

# for tkey in tokentotals.keys():
#     if tkey in inputsetup:
#         id = inputsetup[tkey]["txid"]
#         index = inputsetup[tkey]["txindex"]
#         log("id and utxo with token", [id, utxos[index]], t)
#         txinlist = TransactionInput.from_primitive([id, index])
#         if not id in usedutxos:
#             txins.append(txinlist)
#             total_lovelace_from_inputs += inputsetup[tkey]["tokenqty"]
#             usedutxos.add(id)
# log("txins", txins, t)

# log("addr", addr, t)
# log("usedutxos", usedutxos, t)
# log("total_lovelace_from_inputs", total_lovelace_from_inputs, t)


# # change
# # TODO tally leftovers of all tokens and send back to sender. Find the missing lovelace utxo.
# total_lovelace_from_token_inputs = 0
# difference = 0
# for inputkey, input in inputsetup.items():
#     if "lovelaces" in input:
#         total_lovelace_from_token_inputs += input["lovelaces"]
# differencecheck = total_lovelace_from_token_inputs - (
#     tokentotals["lovelace"]["quantity"] + minfee
# )
# log("differencecheck", differencecheck, t)
# if differencecheck >= 0:
#     difference = differencecheck
# else:
#     for utxoi, utxo in enumerate(utxos):
#         if (
#             not "lovelace" in tokentotals
#         ):  # set lovelace to 1500000 if non-specified in tokentotals
#             tokentotals["lovelace"] = {"unit": "lovelace", "quantity": 1500000}
#         if not str(utxo.input.transaction_id) in usedutxos:
#             if utxo.output.amount.coin + differencecheck >= 0:
#                 # sufficient amount
#                 log("amount sufficient", utxo.output.amount.coin, t)
#                 sufficientadatxs.append(
#                     {
#                         str(utxo.output.amount.coin): {
#                             "index": utxoi,
#                             "txid": utxo.input.transaction_id,
#                         }
#                     }
#                 )
#                 sufficientadatxs = sorted(
#                     sufficientadatxs, key=lambda d: list(d.keys())
#                 )
#             else:  # insufficient amounts
#                 log("amount insufficient", utxo.output.amount.coin, t)
#                 insufficientadatxs.append(
#                     {
#                         str(utxo.output.amount.coin): {
#                             "index": utxoi,
#                             "txid": utxo.input.transaction_id,
#                         }
#                     }
#                 )
#                 insufficientadatxs = sorted(
#                     insufficientadatxs, key=lambda d: list(d.keys()), reverse=t
#                 )

# log("sufficientadatxs", sufficientadatxs, t)
# log("insufficientadatxs", insufficientadatxs, t)
# if len(sufficientadatxs) > 0:  # take ada from first, lowest sufficient utxo
#     utxo = dict(sufficientadatxs[0])  # first sufficient utxo
#     utxoamount = list(utxo.keys())[0]  # amount in utxo
#     id = str(utxo[utxoamount]["txid"])  # id of utxo
#     index = utxo[utxoamount]["index"]  # index of utxo
#     log("First sufficient tx, amount, tx index", [utxo, utxoamount, utxoi], f)
#     txinlist = TransactionInput.from_primitive([id, index])
#     if not id in usedutxos:
#         txins.append(txinlist)
#         total_lovelace_from_inputs += utxoamount
#         usedutxos.add(id)
#     # calculate difference in lovelace (first sufficient - requested amount)
#     # min_gte = tokentotals["lovelace"]["quantity"] >= 1000000
#     # utxooutputamount = int(utxos[utxoi].output.amount.coin - 1000000)
#     difference = int(utxoamount) + differencecheck
# else:
#     target = 0
#     # todo do the same as lovelace for all tokens
#     log("add up insufficients", "", t)
#     for insufamount in insufficientadatxs:
#         log("insufamount", insufamount, t)
#         utxo = dict(insufamount)  # first sufficient utxo
#         utxoamount = list(utxo.keys())[0]  # amount in utxo
#         id = str(utxo[utxoamount]["txid"])  # id of utxo
#         index = utxo[utxoamount]["index"]  # index of utxo
#         if target + differencecheck < 0:
#             target += int(list(insufamount.keys())[0])
#             txinlist = TransactionInput.from_primitive([id, index])
#             if not id in usedutxos:
#                 txins.add(txinlist)
#                 total_lovelace_from_inputs += utxoamount
#                 usedutxos.add(id)
#         else:
#             log("target met", target, f)
#             difference = target + differencecheck
#     targetdiff = 0
#     if target < (differencecheck * -1):
#         targetdiff = target + differencecheck
#         log("targetdiff", targetdiff, t)
#     else:
#         log("target acquired", target, t)

# log("target + differencecheck", targetdiff, t)
# log(
#     "total_lovelace_from_token_inputs, difference",
#     [total_lovelace_from_token_inputs, difference],
#     t,
# )

# txouts = []

# for output in outputlist:
#     if not "tokens" in output:
#         txouts.append(
#             TransactionOutput(Address.decode(output["address"]), output["lovelace"])
#         )
#     else:
#         multi = [1000000, {}]
#         for tokenkey, tokenamount in output["tokens"].items():
#             if tokenkey == "lovelace":
#                 if targetdiff < 0 and tokenamount + targetdiff >= 1000000:
#                     multi[0] = tokenamount + targetdiff
#                     targetdiff = 0
#                 else:
#                     multi[0] = tokenamount
#             else:
#                 log("tokenkey", tokenkey, f)
#                 policy_id = bytes.fromhex(tokenkey[0:56])
#                 token_name = bytes.fromhex(tokenkey[56:])
#                 multi[1][policy_id] = {token_name: tokenamount}
#         txouts.append(
#             TransactionOutput(
#                 Address.decode(output["address"]), Value.from_primitive(multi)
#             )
#         )
# changemulti = [difference if difference > 1000000 else 1000000]
# for policykey, qty in leftovers.items():
#     policy_id = bytes.fromhex(policykey)
#     token_name = alltokens[policykey]["name"].to_primitive()
#     if qty > 0:
#         if len(changemulti) == 1:
#             changemulti.append({})
#         changemulti[1][policy_id] = {token_name: qty}
# log(f"changemulti", changemulti, t)
# txouts.append(TransactionOutput(addr, Value.from_primitive(changemulti)))

# if "metadata" in jsondata:
#     auxiliary_data = AuxiliaryData(
#         AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
#     )

# # TODO add and test metadata
# for inp in txins:
#     log(f"txin", inp, t)
# for out in txouts:
#     log(f"txout", out, t)

tx_body = TransactionBody(inputs=tx_inputs, outputs=tx_outputs, fee=minfee)
log("tx_body", tx_body, t)

signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

tx_id = str(signed_tx.id)

log("signed_tx and id", [signed_tx, tx_id], f)
log("############### Submitting transaction ###############", "", t)

context.submit_tx(signed_tx.to_cbor())
