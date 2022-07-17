from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List


# todo create log module for import to other files
t = True
f = False
dev = t


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


args = sys.argv[1:] or [
    '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"58202c2066ed218b7c9308526077bcf1e3a0a81a4da99767ce0746093f6e09272e9c"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"58207533eaba8c8636c0a4bc62aeebbe44a9490aea888aca9ebf5123b768b85790ab"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"5820e59e3e2687eb9f77f3c4ab6b08678c0c358b87652e4b7f5a29b4882a17036530"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820d3028f37465a91da25385e6b28eeaa3fc684bb37c2c245ad0ff943991a4d1f33"}}}',
    '{"address":"addr1q9nzv2662ey4kkx96makz82q99wwzehs2uzrt9wwyttq723xkkkcpe0xgfzya3g0jzz825fyfzwm7melppsjr3uw72qs7am8ys","outputs":[{"address":"addr1qxp3rgz76qswp87lg5aegtydh9uxcet00q2h9596wdlykk35hk7hhd6z49vwsylqcl29jq9svvagdjdgt7xy2eakv8vqhzmyes","tokens":[{"index":"0","quantity":"13007747","unit":"lovelace"},{"unit":"ef86d15fdc26f796f22582bdafa4369d13e8cd47ef0480b6f57dc89950616e6a7461726120546f6b656e","quantity":"1","index":"1","name":"Panjtara Token"}]}],"submit":"true"}',
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
bf_api = blockfrost.BlockFrostApi(bf)
# log('api from BF', bf_api, f)


sk = PaymentSigningKey.from_cbor(pkey)
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive(jsondata["address"])
addr = address

utxos_from_bf = context.utxos(str(address))
d = jsondata

state = {
    "balance": {
        "in": {"lovelace": 0},
        "out": {"lovelace": 0},
        "remaining": {},
        "insufficient_first": set(),
        "extra": {}
    },
    "pos": { # Possible tx selections
        'suf': set(),
        'insuf': set(),
        'shared': set()
    },
    "minada": 2000000,
    "minfee": 200000,
    "sendall": f,  # TODO put option on front end
    "sufficient": {},
    "insufficient": {},
    "sendall": d['submit'],
    "tokens": {},
    "tokens_required": {},
    "tx_inputs": [],
    "tx_outputs": [],
    "utxos": {},
}
s = state

for output in d['outputs']:
    log("output", output, t)
    lovelace = 0
    multi = {}
    for token in output["tokens"]:
        if token["unit"] in s['tokens_required']:
            s['tokens_required'][token["unit"]] += int(token["quantity"])
        else:
            s['tokens_required'][token["unit"]] = int(token["quantity"])
        if token['unit'] == 'lovelace':
            lovelace = int(token['quantity']) if int(token['quantity']) > s['minada'] else s['minada']
            if not 'lovelace' in s['balance']['out']:
                s['balance']['out']['lovelace'] = 0
            s['balance']['out']['lovelace'] += int(token['quantity'])
        else:
            multi[bytes.fromhex(token['unit'][0:56])] = {
                bytes(token['name'], 'utf-8'): int(token['quantity'])
            }
            if not token['unit'][0:56] in s['balance']['out']:
                s['balance']['out'][token['unit'][0:56]] = 0
            s['balance']['out'][token['unit'][0:56]] += int(token['quantity'])
        
        
    log('multi', multi, t)
    log('lovelace', lovelace, t)
    s['tx_outputs'].append(
        TransactionOutput(
            Address.decode(output['address']), 
            Value.from_primitive([lovelace, multi] if len(multi.keys()) > 0 else lovelace)
        )
    )
    
    
s['balance']['remaining'] = s['tokens_required']
for utxoindex, utxo in enumerate(utxos_from_bf):
        log("utxo:" + str(utxoindex), utxo, f)
        tx_id = str(utxo.input.transaction_id)
        coin = utxo.output.amount.coin
        index = utxo.input.index

        # UTXO Setups (dealing with multiple inputs from same tx)
        if not tx_id in s['utxos']:
            s['utxos'][tx_id] = {}
        s['utxos'][tx_id][index] = {"lovelace": coin}
        if coin >= s['tokens_required']["lovelace"]:
            if not "lovelace" in s.insufficient:
                s['sufficient']["lovelace"] = {"tx_id": tx_id, "index": index, "coin": coin}
            else:
                s['sufficient']["lovelace"].append(
                    {"tx_id": tx_id, "index": index, "coin": coin}
                )
        else:
            if not "lovelace" in s['insufficient']:
                s['insufficient']["lovelace"] = [
                    {"tx_id": tx_id, "index": index, "coin": coin}
                ]
            else:
                s['insufficient']["lovelace"].append(
                    {"tx_id": tx_id, "index": index, "coin": coin}
                )
        if len(utxo.output.amount.multi_asset.keys()) > 0:
            for tokenkey in utxo.output.amount.multi_asset.keys():
                policy_id = tokenkey.to_primitive().hex()
                b_name = list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
                hex_name = (
                    list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
                    .to_primitive()
                    .hex()
                )
                s['utxos'][tx_id][utxo.input.index][policy_id] = utxo.output.amount.multi_asset[
                    tokenkey
                ][b_name]
                s['tokens'][policy_id] = {
                    "amount": s['utxos'][tx_id][utxo.input.index][policy_id],
                    "b_name": b_name,
                    "hex_name": hex_name,
                    "policy_id": policy_id,
                    "policy_script": tokenkey,
                }
                token = s['tokens'][policy_id]
                # m_token = m_tokens[policy_id]
                if (policy_id + hex_name) in s['tokens_required']:
                    if token["amount"] >= s['tokens_required'][policy_id + hex_name]:
                        if not policy_id + hex_name in s['sufficient']:
                            s['sufficient'][policy_id + hex_name] = [
                                {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                            ]
                        else:
                            s['sufficient'][policy_id + hex_name].append(
                                {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                            )
                    else:
                        if not policy_id + hex_name in s['insufficient']:
                            s['insufficient'][policy_id + hex_name] = [
                                {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                            ]
                        else:
                            s['insufficient'][policy_id + hex_name].append(
                                {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                            )
# Sort sufficient (low-high) and insufficient (high-low)
# Check if same txs exist in both sufficient and insufficient

for token, txs in s['sufficient'].items():
    s['sufficient'][token] = sorted(s['sufficient'][token], key=lambda d: d["coin"])
    for tx in txs:
        s['pos']['suf'].add(json.dumps({tx['tx_id']: tx['index']}))

for token, txs in s['insufficient'].items():
    s['insufficient'][token] = sorted(s['insufficient'][token], key=lambda d: d["coin"], reverse=t)
    for tx in txs:
        s['pos']['insuf'].add(json.dumps({tx['tx_id']: tx['index']}))
        s['balance']['insufficient_first'].add(token)
        if json.dumps({tx['tx_id']: tx['index']}) in list(s['pos']['suf']):
            s['pos']['shared'].add(json.dumps({tx['tx_id']: tx['index']}))

log('utxos', s['utxos'], t)
log('tokens_required', s['tokens_required'], t)
log('sufficient', s['sufficient'], f)
log('insufficient', s['insufficient'], f)
log('pos', s['pos'], f)

# First include shared pos txs then recalculate remains
for input in s['pos']['shared']:
    inp_tx = list(json.loads(input).keys())[0]
    inp_index = json.loads(input)[inp_tx]
    s['tx_inputs'].append(TransactionInput.from_primitive([inp_tx, inp_index]))
    log('utxos token', s['utxos'][inp_tx][inp_index], t)
    for token, amount in s['utxos'][inp_tx][inp_index].items():
        if not token in s['balance']['in']:
            s['balance']['in'][token] = 0
        s['balance']['in'][token] += amount
        token_id = 'lovelace' if token == 'lovelace' else token + (s['tokens'][token]['hex_name'])
        if (token_id) in s['balance']['remaining']:
            s['balance']['remaining'][token_id] -= amount
        else:
            if not token in s['balance']['extra']:
                s['balance']['extra'][token] = amount 
            else: 
                s['balance']['extra'][token] += amount
        if token_id in s['insufficient']:
            for i in range(len(s['insufficient'][token_id])):
                if s['insufficient'][token_id][i]['tx_id'] == inp_tx and s['insufficient'][token_id][i]['index'] == inp_index:
                    del s['insufficient'][token_id][i]
        if token_id in s['sufficient']:
            for i in range(len(s['sufficient'][token_id])):
                if s['sufficient'][token_id][i]['tx_id'] == inp_tx and s['sufficient'][token_id][i]['index'] == inp_index:
                    del s['sufficient'][token_id][i]


log('tokens', s['tokens'], f)

# iterate through balance.remaining to match best sufficient if enough, else insuf.
for token, amount in s['balance']['remaining'].items():
    if amount > 0:
        if token in s['sufficient'] and len(s['sufficient'][token]) > 0:
            log('sufficient', s['sufficient'][token], f)
            for tx in s['sufficient'][token]:
                inp_tx = tx['tx_id']
                inp_index = tx['index']
                s['tx_inputs'].append(TransactionInput.from_primitive([inp_tx, inp_index]))
                log('utxos token', s['utxos'][inp_tx][inp_index], t)
                for extra_token, extra_amount in s['utxos'][inp_tx][inp_index].items():
                    if extra_token != token:
                        if not extra_token in s['balance']['extra']:
                            s['balance']['extra'][extra_token] = extra_amount 
                        else: 
                            s['balance']['extra'][extra_token] += extra_amount 
                if not token in s['balance']['in']:
                    s['balance']['in'][token] = 0
                s['balance']['in'][token] += tx['coin']
            for i in range(len(s['sufficient'][token]) - 1):
                if s['sufficient'][token][i]['tx_id'] == inp_tx and s['sufficient'][token][i]['index'] == inp_index:
                    del s['sufficient'][token][i]
        if token in s['insufficient'] and len(s['insufficient'][token]) > 0:
            log('insufficient', s['insufficient'][token], f)
            for tx in s['insufficient'][token]:
                inp_tx = tx['tx_id']
                inp_index = tx['index']
                s['tx_inputs'].append(TransactionInput.from_primitive([inp_tx, inp_index]))
                log('utxos token', s['utxos'][inp_tx][inp_index], t)
                for extra_token, extra_amount in s['utxos'][inp_tx][inp_index].items():
                    if extra_token != token:
                        if not extra_token in s['balance']['extra']:
                            s['balance']['extra'][extra_token] = extra_amount 
                        else: 
                            s['balance']['extra'][extra_token] += extra_amount 
                if not token in s['balance']['in']:
                    s['balance']['in'][token] = 0
                s['balance']['in'][token] += tx['coin']
                if (token_id) in s['balance']['remaining']:
                    s['balance']['remaining'][token] -= amount
                if s['balance']['in'][token] >= amount:
                    break
            for i in range(len(s['insufficient'][token]) - 1):
                if s['insufficient'][token][i]['tx_id'] == inp_tx and s['insufficient'][token][i]['index'] == inp_index:
                    del s['insufficient'][token][i]

                # deal with return after balancing
for token, amount in s['balance']['in'].items():
    if token in s['balance']['out'] and s['balance']['in'][token] > s['balance']['out'][token]:
        if not token in s['balance']['extra']:
            s['balance']['extra'][token] = amount - s['balance']['out'][token]
        else: 
            s['balance']['extra'][token] += amount - s['balance']['out'][token]

s['balance']['extra']['lovelace'] -= s['minfee']
if len(s['balance']['extra'].keys()) >= 1 or s['balance']['extra']['lovelace'] > 0:
    if s['balance']['extra']['lovelace'] < s['minada']:
        if 'lovelace' in s['insufficient'] and len(s['insufficient']['lovelace']) > 0:
            log(type(s['insufficient']['lovelace']), s['insufficient']['lovelace'], t)
            s['insufficient']['lovelace'].reverse()
            for tx in s['insufficient']['lovelace']:
                inp_tx = tx['tx_id']
                inp_index = tx['index']
                s['tx_inputs'].append(TransactionInput.from_primitive([inp_tx, inp_index]))
                for extra_token, extra_amount in s['utxos'][inp_tx][inp_index].items():
                    if extra_token != token:
                        if not extra_token in s['balance']['extra']:
                            s['balance']['extra'][extra_token] = extra_amount 
                        else: 
                            s['balance']['extra'][extra_token] += extra_amount 
                s['balance']['in']['lovelace'] += tx['coin']
                if s['balance']['in']['lovelace'] >= s['minada']:
                    break

    return_multi = {}
    for token, amount in s['balance']['extra'].items():
        if token == 'lovelace':
            return_lovelace = amount
        else:
            log('token', token, t)
            return_multi[bytes.fromhex(token)] = {
                bytes.fromhex(s['tokens'][token]['hex_name']): amount
            }
    log('returning', [return_lovelace, return_multi], t)
    s['tx_outputs'].append(
        TransactionOutput(
            address, 
            Value.from_primitive([return_lovelace, return_multi] if len(return_multi.keys()) > 0 else return_lovelace)
        )
    )
                # almost done. ur slow but a genius sometimes.
                # balance the ins and outs with return for future debugging
                # if u want extra credit, make a balancing function so not to repeat.

log('sufficient', s['sufficient'], t)
log('insufficient', s['insufficient'], t)
log('tx_inputs', s['tx_inputs'], t)
log('tx_outputs', s['tx_outputs'], t)
log('balance', s['balance'], t)



##################################### stop fixing stupid code
# # Fetch utxo data
# utxos_from_bf = context.utxos(str(address))
# # TODO: allow multiple inputs

# Instantiate structs and values




def run_init(): 

#     # functions

#     def calculate_balance_in(tx_id):
#         minting_utxo[tx_id] = f
#         if not tx_id in usedutxos:
#             log(f"Calculating return from utxo: {tx_id}", utxos[tx_id], f)
#             balance["in"]["lovelace"] += utxos[tx_id]["lovelace"]
#             if not tx_id in balance["by_tx"]:
#                 balance["by_tx"][tx_id] = {}
#             balance["by_tx"][tx_id]["lovelace"] = utxos[tx_id]["lovelace"]
#             for key, token in utxos[tx_id]["tokens"].items():
#                 # log("fkn token data", bf_api.asset(key), f)
#                 if not key in balance["in"]:
#                     balance["in"][key] = 0
#                 balance["in"][key] += token["amount"]
#                 balance["by_tx"][tx_id][key] = token["amount"]
#             usedutxos.add(tx_id)
#         else:
#             log(f"Already calculated: {tx_id}", utxos[tx_id], f)
#     def calc_in(tx):
#         log("Calculating input", tx)
#         # m_balance
#     def calculate_return():
#         return_leftovers = [0]
#         if len(balance["in"].keys()) > 1:
#             return_leftovers.append({})
#         for token_key, token_amount in balance["in"].items():
#             log("balance['in']" + token_key, token_amount, f)
#             if not token_key in balance["out"]:
#                 log("must return: " + token_key, token_amount, f)
#                 return_leftovers[1][tokens[token_key]["policy_script"].to_primitive()] = {
#                     tokens[token_key]["b_name"].to_primitive(): int(token_amount)
#                 }
#             else:
#                 if token_key == "lovelace":
#                     return_leftovers[0] = token_amount - balance["out"][token_key] - minfee
#                 else:
#                     return_leftovers[1][
#                         tokens[token_key]["policy_script"].to_primitive()
#                     ] = {
#                         tokens[token_key]["b_name"].to_primitive(): int(token_amount)
#                         - balance["out"][token_key]
#                     }
#         log("return_leftovers", return_leftovers, f)
#         tx_outputs.append(
#             TransactionOutput(
#                 Address.decode(address), Value.from_primitive(return_leftovers)
#             )
#         )


#     # if not sendall:
#     #     return_tokens["lovelace"] = minada
#     #     total_tokens_required["lovelace"] = minfee

#     for output in jsondata["outputs"]:  # Get outputs from api request
#         log("output", output, f)
#         prepmulti = {}  # prepare for multi
#         outputbyaddress[output["address"]] = {}  # set output address
#         outputbyaddress[output["address"]]["lovelace"] = minada  # set minada to be replaced
#         for token in output["tokens"]:
#             outputbyaddress[output["address"]][token["unit"]] = token["quantity"]
#             if token["unit"] in total_tokens_required:
#                 total_tokens_required[token["unit"]] += int(token["quantity"])
#                 m_tokens_required[token["unit"]] += int(token["quantity"])

#             else:
#                 total_tokens_required[token["unit"]] = int(token["quantity"])
#                 m_tokens_required[token["unit"]] = int(token["quantity"])
#             log(
#                 "TOKEN output: " + token["unit"],
#                 outputbyaddress[output["address"]][token["unit"]],
#                 t,
#             )
#             log("TOKEN required: " + token["unit"], total_tokens_required[token["unit"]], f)

#     # Create Inputs (TransactionInput.from_primitive([id, index]))
#     # Calculate return change

#     for token, amount in m_sufficient.items():
#         # Sort txs: by smallest sufficient and by largest insufficient
#         if token in m_sufficient:
#             m_sufficient_sorted[token] = sorted(
#                 m_sufficient[token], key=lambda d: d["coin"]
#             )
#             log(f"sufficient_sorted: {token}", m_sufficient_sorted[token], f)

#         if token in m_insufficient:
#             m_insufficient_sorted[token] = sorted(
#                 m_insufficient[token], key=lambda d: d["coin"], reverse=t
#             )
#             log(f"insufficient_sorted: {token}", m_insufficient_sorted[token], f)

#     # Is the token fully covered by sufficients?
#     for token, index in m_sufficient.items():
#         if token in total_tokens_required:
#             include_sufficient_txs.append({token: index})
#         else:
#             include_insufficient_txs.append({token: index})
#             insufficient_first = t
#     log("include_insufficient_txs", include_insufficient_txs, t)
#     log("include_sufficient_txs", include_sufficient_txs, t)
#     log("insufficient_first", insufficient_first, t)

#     if insufficient_first:
#         for tx in m_insufficient_sorted:
#             calc_in(tx)
#     # If not, and we need to take from insufficients, adding them in first

#     for token, amount in total_tokens_required.items():
#         log("Are we calculating this required token? " + token, amount, f)
#         log("sufficienttxs[token]", sufficienttxs[token], f)
#         if token in sufficienttxs:
#             log("token sufficient", token, f)
#             sufficient_sorted[token] = sorted(sufficienttxs[token], key=lambda d: d.keys())
#             log("sufficient_sorted", sufficient_sorted, f)
#             if len(sufficient_sorted[token]) > 0:
#                 key = list(sufficient_sorted[token][0].keys())[0]
#                 tx_id = sufficient_sorted[token][0][key]
#                 log("sufficient_sorted[token][0]", tx_id, f)
#                 # return_tokens[token] = target - int(amount)
#                 if not tx_id in usedutxos:
#                     totals["inputs"][tx_id] = {
#                         token: list(sufficient_sorted[token][0].keys())[0]
#                     }
#                     tx_inputs.append(
#                         TransactionInput.from_primitive([tx_id, utxos[tx_id]["index"]])
#                     )
#         calculate_balance_in(tx_id)

#         if token in insufficienttxs:
#             log("token insufficient", token, f)
#             insufficient_sorted[token] = sorted(
#                 insufficienttxs[token], key=lambda d: d.keys(), reverse=t
#             )
#             target = 0
#             for partial in insufficient_sorted[token]:
#                 partial_tuple = list(partial.items())[0]
#                 partial_amount = partial_tuple[0]
#                 partial_id = partial_tuple[1]
#                 target += int(partial_amount)
#                 if not partial_id in usedutxos:
#                     totals["inputs"][partial_id] = {token: partial_tuple[0]}
#                     tx_inputs.append(
#                         TransactionInput.from_primitive(
#                             [partial_id, utxos[partial_id]["index"]]
#                         )
#                     )
#                     log(
#                         "Have we already calculated this required token? " + token,
#                         amount,
#                         t,
#                     )
#                 calculate_balance_in(partial_id)
#                 #   total_tokens_input['lovelace'] += utxos[tx_id]['lovelace']
#                 log("target", [target, int(amount)], f)
#                 if target >= int(amount):
#                     break
#     # return_tokens["lovelace"] = (
#     #     total_tokens_input["lovelace"] - total_tokens_required["lovelace"]
#     # )
#     # outputbyaddress[str(address)] = return_tokens
#     log("outputbyaddress", outputbyaddress, f)
#     log("tokens", tokens, f)
#     for address, output in outputbyaddress.items():
#         log(f"Output: {address}", output, f)
#         if len(output.keys()) > 1:
#             multi = {}
#             for policy_id, amount in output.items():
#                 log(f"output item: {policy_id}", amount, f)
#                 if not policy_id == "lovelace":
#                     log(policy_id, amount, f)
#                     if not policy_id[0:56] in balance["out"]:
#                         balance["out"][policy_id[0:56]] = 0
#                     balance["out"][policy_id[0:56]] += int(amount)
#                     multi[tokens[policy_id[0:56]]["policy_script"].to_primitive()] = {
#                         tokens[policy_id[0:56]]["b_name"].to_primitive(): int(amount)
#                     }
#                     log("multi", multi, f)
#                 else:
#                     if not "lovelace" in balance["out"]:
#                         balance["out"]["lovelace"] = 0
#                     balance["out"]["lovelace"] += int(amount)
#                     log(policy_id, output["lovelace"], f)

#             if int(output["lovelace"]) >= minada:
#                 # if not "lovelace" in balance["out"]:
#                 #     balance["out"]["lovelace"] = 0
#                 # balance["out"]["lovelace"] += int(amount)
#                 tx_outputs.append(
#                     TransactionOutput(
#                         Address.decode(address),
#                         Value.from_primitive([int(output["lovelace"]), multi]),
#                     )
#                 )
#         else:
#             if int(output["lovelace"]) >= minada:
#                 if not "lovelace" in balance["out"]:
#                     balance["out"]["lovelace"] = 0
#                 balance["out"]["lovelace"] += int(output["lovelace"])
#                 tx_outputs.append(
#                     TransactionOutput(
#                         Address.decode(address),
#                         Value.from_primitive([int(output["lovelace"])]),
#                     )
#                 )
#             # else:

#     log("Balance", balance, t)
#     calculate_return()
#     # for token, amount in balance["in"].items():
#     #     if not token in balance["out"]:
#     #         log("Error: Token not in!", token, f)
#     #     balance["dif"][token] = amount - balance["out"][token]

#     log("utxos_from_bf", utxos_from_bf, f)
#     log("utxos", utxos, f)
#     log("outputbyaddress", outputbyaddress, f)
#     log("total_tokens_required", total_tokens_required, f)
#     log("total_tokens_input", total_tokens_input, f)
#     log("sufficienttxs", sufficienttxs, f)
#     log("insufficienttxs", insufficienttxs, f)
#     log("usedutxos", usedutxos, f)
#     log("return_tokens", return_tokens, f)
#     log("tokens", tokens, f)
#     log("totals", totals, f)
#     log("tx_inputs", tx_inputs, f)
#     log("tx_outputs", tx_outputs, f)
#     log("balance", balance, f)

#     if "metadata" in jsondata:
#         auxiliary_data = AuxiliaryData(
#             AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
#         )

#     tx_body = TransactionBody(inputs=tx_inputs, outputs=tx_outputs, fee=minfee)
#     log("tx_body", tx_body, f)

#     signature = sk.sign(tx_body.hash())
#     vk_witnesses = [VerificationKeyWitness(vk, signature)]
#     signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

#     tx_id = str(signed_tx.id)

#     log("signed_tx and id", [signed_tx, tx_id], f)
#     log("############### Submitting transaction ###############", "", f)

#     if jsondata["submit"] == "true":
#         context.submit_tx(signed_tx.to_cbor())
#         if not dev:
#             print(tx_id)
#     else:
#         # print(builder._fee)
#         if not dev:
#             print(json.dumps([tx_id, signed_tx.to_cbor()]))
    return
