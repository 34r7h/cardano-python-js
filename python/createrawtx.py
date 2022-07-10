from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

t = True
f = False
dev = f

def log(l, d, s):
    if not dev:
        return
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

args = sys.argv[1:]

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
balance = {
    "in": {"lovelace": 0},
    "out": {"lovelace": 0}
}
insufficienttxs = {"lovelace": []}
insufficient_sorted = {}
outputbyaddress = {}
minada = 2000000
minfee = 200000
sendall = f  # TODO put option on front end
sufficienttxs = {"lovelace": []}
sufficient_sorted = {}
tokens = {}
total_tokens_required = {"lovelace": minfee}
tx_inputs = []
tx_outputs = []
usedutxos = set()
utxos = {}

# functions
def calculate_balance_in(tx_id):
    log(f"Calculating return from utxo: {tx_id}", utxos[tx_id], t)
    if not tx_id in usedutxos:
        balance["in"]["lovelace"] += utxos[tx_id]["lovelace"]
        for key, token in utxos[tx_id]["tokens"].items():
            if not key in balance["in"]:
                balance["in"][key] = 0
            balance["in"][key] += token["amount"]
        usedutxos.add(tx_id)

def calculate_return():
    return_leftovers = [0]
    if len(balance['in'].keys()) > 1:
        return_leftovers.append({})
    for token_key, token_amount in balance['in'].items():
        log("balance['in']" + token_key, token_amount, t)
        if not token_key in balance['out']:
            log('must return: '+token_key, token_amount, t)
            return_leftovers[1][tokens[token_key]["policy_script"].to_primitive()] = {
                tokens[token_key]["b_name"].to_primitive(): int(token_amount)
            }
        else:
            if token_key == 'lovelace':
                return_leftovers[0] = token_amount - balance['out'][token_key] - minfee
            else:
                return_leftovers[1][tokens[token_key]["policy_script"].to_primitive()] = {
                tokens[token_key]["b_name"].to_primitive(): int(token_amount) - balance['out'][token_key]
            }
    log('return_leftovers', return_leftovers, t)
    tx_outputs.append(
        TransactionOutput(address, Value.from_primitive(return_leftovers))
    )

if not sendall:
    total_tokens_required["lovelace"] = minfee

for output in jsondata["outputs"]:  # Get outputs from api request
    log("output", output, f)
    prepmulti = {}  # prepare for multi
    outputbyaddress[output["address"]] = {}  # set output address
    outputbyaddress[output["address"]]["lovelace"] = minada  # set minada to be replaced
    for token in output["tokens"]:
        outputbyaddress[output["address"]][token["unit"]] = token["quantity"]
        if token["unit"] in total_tokens_required:
            total_tokens_required[token["unit"]] += int(token["quantity"])
        else:
            total_tokens_required[token["unit"]] = int(token["quantity"])
        log( 'TOKEN output: ' + token["unit"], outputbyaddress[output["address"]][token["unit"]], t)
        log( 'TOKEN required: ' + token["unit"],total_tokens_required[token["unit"]], t)

for utxoindex, utxo in enumerate(utxos_from_bf):
    log("utxo:" + str(utxoindex), utxo, f)
    tx_id = str(utxo.input.transaction_id)
    coin = utxo.output.amount.coin
    index = utxo.input.index
    utxos[tx_id] = {"lovelace": utxo.output.amount.coin, "tokens": {}, "index": index}
    if coin >= total_tokens_required["lovelace"]:
        sufficienttxs["lovelace"].append({str(coin): tx_id})
    else:
        insufficienttxs["lovelace"].append({str(coin): tx_id})
    log('LOVELACE utxo:' + tx_id, str(coin), t)
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
            tokens[policy_id] = utxos[tx_id]["tokens"][policy_id]

            token = utxos[tx_id]["tokens"][policy_id]
            if (policy_id + hex_name) in total_tokens_required:
                if token["amount"] >= total_tokens_required[policy_id + hex_name]:
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
                log('TOKEN utxo: ' + tx_id, token, t)

log("total_tokens_required", total_tokens_required, f)
log("utxos", utxos, f)
for token, amount in total_tokens_required.items():
    log("Are we calculating this required token? " + token, amount, t)
    log("sufficienttxs[token]", sufficienttxs[token], f)
    if token in sufficienttxs:
        log("token sufficient", token, t)
        sufficient_sorted[token] = sorted(sufficienttxs[token], key=lambda d: d.keys())
        log("sufficient_sorted", sufficient_sorted, f)
        if len(sufficient_sorted[token]) > 0:
            key = list(sufficient_sorted[token][0].keys())[0]
            tx_id = sufficient_sorted[token][0][key]
            log("sufficient_sorted[token][0]", tx_id, f)
            if not tx_id in usedutxos:
                tx_inputs.append(
                    TransactionInput.from_primitive([tx_id, utxos[tx_id]["index"]])
                )
    calculate_balance_in(tx_id)

    if token in insufficienttxs:
        log("token insufficient", token, t)
        insufficient_sorted[token] = sorted(
            insufficienttxs[token], key=lambda d: d.keys(), reverse=t
        )
        target = 0
        for partial in insufficient_sorted[token]:
            partial_tuple = list(partial.items())[0]
            partial_amount = partial_tuple[0]
            partial_id = partial_tuple[1]
            target += int(partial_amount)
            if not partial_id in usedutxos:
                tx_inputs.append(
                    TransactionInput.from_primitive(
                        [partial_id, utxos[partial_id]["index"]]
                    )
                )
                log(
                    "Have we already calculated this required token? " + token,
                    amount,
                    t,
                )
            calculate_balance_in(partial_id)
            log("target", target, f)
            if target > int(amount):
                break

log("outputbyaddress", outputbyaddress, t)
log("tokens", tokens, f)
for output_address, output in outputbyaddress.items():
    log(f"Output: {output_address}", output, t)
    if len(output.keys()) > 1:
        multi = {}
        for policy_id, amount in output.items():
            log(f"output item: {policy_id}", amount, t)
            if not policy_id == "lovelace":
                log(policy_id, amount, f)
                if not policy_id[0:56] in balance["out"]:
                    balance["out"][policy_id[0:56]] = 0
                balance["out"][policy_id[0:56]] += int(amount)
                multi[tokens[policy_id[0:56]]["policy_script"].to_primitive()] = {
                    tokens[policy_id[0:56]]["b_name"].to_primitive(): int(amount)
                }
                log("multi", multi, f)
            else:
                if not "lovelace" in balance["out"]:
                    balance["out"]["lovelace"] = 0
                balance["out"]["lovelace"] += int(amount)
                log(policy_id, output["lovelace"], t)

        if int(output["lovelace"]) >= minada:
            tx_outputs.append(
                TransactionOutput(
                    Address.decode(output_address),
                    Value.from_primitive([int(output["lovelace"]), multi]),
                )
            )
    else:
        if int(output["lovelace"]) >= minada:
            if not "lovelace" in balance["out"]:
                balance["out"]["lovelace"] = 0
            balance["out"]["lovelace"] += int(output["lovelace"])
            tx_outputs.append(
                TransactionOutput(
                    Address.decode(output_address),
                    Value.from_primitive([int(output["lovelace"])]),
                )
            )
calculate_return()

log("utxos_from_bf", utxos_from_bf, f)
log("utxos", utxos, f)
log("outputbyaddress", outputbyaddress, t)
log("total_tokens_required", total_tokens_required, t)
log("sufficienttxs", sufficienttxs, f)
log("insufficienttxs", insufficienttxs, f)
log("usedutxos", usedutxos, t)
log("tokens", tokens, t)
log("tx_inputs", tx_inputs, t)
log("tx_outputs", tx_outputs, t)
log("balance", balance, t)

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

tx_body = TransactionBody(inputs=tx_inputs, outputs=tx_outputs, fee=minfee)
log("tx_body", tx_body, f)
signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
tx_id = str(signed_tx.id)

log("signed_tx and id", [signed_tx, tx_id], f)
log("############### Submitting transaction ###############", "", t)
if jsondata["submit"] == "true":
    context.submit_tx(signed_tx.to_cbor())
    if not dev:
        print(tx_id)
else:
    if not dev:
        print(json.dumps([tx_id, signed_tx.to_cbor()]))