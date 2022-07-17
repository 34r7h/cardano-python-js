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
    "submit": d['submit'],
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
                if (token) in s['balance']['remaining']:
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


if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

tx_body = TransactionBody(inputs=s['tx_inputs'], outputs=s['tx_outputs'], fee=s['minfee'])
log("tx_body", tx_body, f)

signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))

tx_id = str(signed_tx.id)

log("signed_tx and id", [signed_tx, tx_id], t)
log("############### Submitting transaction ###############", "", t)

if s["submit"] == "true":
    context.submit_tx(signed_tx.to_cbor())
    print(tx_id)
else:
    # print(builder._fee)
    if not dev:
        print(json.dumps([tx_id, signed_tx.to_cbor()]))
