from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

t = True
f = False
dev = t

args = sys.argv[1:] or [
    "{\"payment\":{\"signing\":{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"PaymentSigningKeyShelley_ed25519\",\"cborHex\":\"58202c2066ed218b7c9308526077bcf1e3a0a81a4da99767ce0746093f6e09272e9c\"},\"verification\":{\"type\":\"PaymentVerificationKeyShelley_ed25519\",\"description\":\"PaymentVerificationKeyShelley_ed25519\",\"cborHex\":\"58207533eaba8c8636c0a4bc62aeebbe44a9490aea888aca9ebf5123b768b85790ab\"}},\"stake\":{\"signing\":{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"StakeSigningKeyShelley_ed25519\",\"cborHex\":\"5820e59e3e2687eb9f77f3c4ab6b08678c0c358b87652e4b7f5a29b4882a17036530\"},\"verification\":{\"type\":\"StakeVerificationKeyShelley_ed25519\",\"description\":\"StakeVerificationKeyShelley_ed25519\",\"cborHex\":\"5820d3028f37465a91da25385e6b28eeaa3fc684bb37c2c245ad0ff943991a4d1f33\"}}}","{\"address\":\"addr1q9nzv2662ey4kkx96makz82q99wwzehs2uzrt9wwyttq723xkkkcpe0xgfzya3g0jzz825fyfzwm7melppsjr3uw72qs7am8ys\",\"outputs\":[{\"address\":\"addr1qxftfc2s95ss6uz242vxzlw3uu6njuzdp6gldjqfjyzyz6hl0zvkw9l9v69763fl3day46p9lzt2vr66s937emalexeqljy59n\",\"tokens\":[{\"index\":\"0\",\"quantity\":\"2651897\",\"unit\":\"lovelace\"},{\"unit\":\"2d93c679676ff59f092b448c942212312267a67eae63f57b4905133177746620636f696e\",\"quantity\":\"1\",\"index\":\"1\",\"name\":\"wtf coin\"},{\"unit\":\"581513d0cdb8a1cd3753a5fd4cf9c2931453253aeb5cf252667ee7244147415045706f6f6c62657461\",\"quantity\":\"18000\",\"index\":\"2\"},{\"unit\":\"cf0718f10faa46e686ec2fbfbde8ef99a7c75ae28026db09e06bb8616c6f76655f6561727468\",\"quantity\":\"1\",\"index\":\"4\",\"name\":\"love_earth\"},{\"unit\":\"ae44f6f2bf702326b8b02b5d902458b99c47de929a7d7922eac4d6be58796d626f6c50726f746f7479706531\",\"quantity\":\"2\",\"index\":\"3\"},{\"unit\":\"da2bd6118fffc30168a1bc19e288244bc25e49892269aca57753292554616e676f\",\"quantity\":\"1000000\",\"index\":\"5\"},{\"unit\":\"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d61\",\"quantity\":\"1\",\"index\":\"6\",\"name\":\"a\"}]}],\"submit\":\"true\"}","mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza"
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
utxos_from_bf = context.utxos(str(address))

d = jsondata

class Methods:
    def l(self, l, d, s): # pretty and informative logging
        if not dev:
            return
        dtype = type(d)
        try:
            da = json.dumps(d, indent=2, sort_keys=t)
        except:
            da = d
        if s:
            print(f"\n\n\n{'─' * 25}\n{l}: {dtype}\n{'─' * 15}\n")
            if type(da) == list or type(da) == set:
                for xi, x in enumerate(da):
                    print(f"{xi}:", x, "\n")
            else:
                print(da)
    
    def extra(self, inp_tx, inp_index, token):
        for extra_token, extra_amount in s["utxos"][inp_tx][inp_index].items():
            if extra_token != token:
                if not extra_token in s["balance"]["extra"]:
                    s["balance"]["extra"][extra_token] = extra_amount
                else:
                    s["balance"]["extra"][extra_token] += extra_amount

    def delist(self, suf, inp_tx, inp_index):
        for token, tx_inputs in s[suf].items():
            for i, tx_input in enumerate(tx_inputs):
                if tx_input['tx_id'] == inp_tx and tx_input['index'] == inp_index:
                    del s[suf][token][i]

    def assign_inputs(self, tx_id, index):
        s["tx_inputs"].append(TransactionInput.from_primitive([tx_id, index]))

    def assign_outputs(self, output_address, output_tokens):
        m.l('o.t.', output_tokens, t)
        s["tx_outputs"].append(
            TransactionOutput(
                Address.decode(output_address),
                Value.from_primitive(
                    [output_tokens['lovelace'], output_tokens['multi']] if len(output_tokens['multi'].keys()) > 0 else [output_tokens['lovelace']]
                )
            )
        )
m = Methods()


state = {
    "balance": {
        "in": {"lovelace": 0},
        "out": {"lovelace": 0},
        "remaining": {},
        "extra": {},
    },
    "pos": {"sufficient": set(), "insufficient": set(), "shared": set()},  # Possible tx selections
    "minada": 2000000,
    "minfee": 200000,
    "sendall": f,  # TODO put option on front end
    "sufficient": {},
    "insufficient": {},
    "suf": {},
    "insuf": {},
    "submit": d["submit"],
    "tokens": {},
    "tokens_required": {},
    "tx": {
        'inputs': set(),
        'outputs': set()
    },
    "tx_inputs": [],
    "tx_outputs": [],
    'used_txs': [], 
    "utxos": {},
}
s = state

m.l('state', s, t)
m.l('data', d, t)

for output in d["outputs"]:
    lovelace = 0
    multi = {}

    # Create dict of total required tokens
    for token in output["tokens"]:
        if token["unit"] in s["tokens_required"]:
            s["tokens_required"][token["unit"]] += int(token["quantity"])
        else:
            s["tokens_required"][token["unit"]] = int(token["quantity"])
        if token["unit"] == "lovelace":
            lovelace = (
                int(token["quantity"])
                if int(token["quantity"]) > s["minada"]
                else s["minada"]
            )
            if not "lovelace" in s["balance"]["out"]:
                s["balance"]["out"]["lovelace"] = 0
            s["balance"]["out"]["lovelace"] += int(token["quantity"])
        else:
            multi[bytes.fromhex(token["unit"][0:56])] = {
                bytes.fromhex(token["unit"][57:-1]): int(token["quantity"])
            }
            if not token["unit"][0:56] in s["balance"]["out"]:
                s["balance"]["out"][token["unit"][0:56]] = 0
            s["balance"]["out"][token["unit"][0:56]] += int(token["quantity"])
            
    # Create requested output
    output_tokens = {
        'lovelace': lovelace,
        'multi': multi
    }
    m.assign_outputs(output["address"], output_tokens)
    
s["balance"]["remaining"] = s["tokens_required"] # Setup remaining balance to return

for utxoindex, utxo in enumerate(utxos_from_bf):
    tx_id = str(utxo.input.transaction_id)
    coin = utxo.output.amount.coin
    index = utxo.input.index

    # UTXO Setup (w/ checks for sufficient or insufficient sorting)
    if not tx_id in s["utxos"]: s["utxos"][tx_id] = {}
    s["utxos"][tx_id][index] = {"lovelace": coin}

    # Add ADA (lovelace) to sufficient or insufficient   
    if coin >= s["tokens_required"]["lovelace"]: 
        if not "lovelace" in s["sufficient"]:
            s["sufficient"]["lovelace"] = [
                {"tx_id": tx_id, "index": index, "coin": coin}
            ]
        else:
            s["sufficient"]["lovelace"].append(
                {"tx_id": tx_id, "index": index, "coin": coin}
            )
    else:
        if not "lovelace" in s["insufficient"]:
            s["insufficient"]["lovelace"] = [
                {"tx_id": tx_id, "index": index, "coin": coin}
            ]
        else:
            s["insufficient"]["lovelace"].append(
                {"tx_id": tx_id, "index": index, "coin": coin}
            )
    # Add each token to tokens, sufficient/insufficient
    if len(utxo.output.amount.multi_asset.keys()) > 0:
        for tokenkey in utxo.output.amount.multi_asset.keys():
            policy_id = tokenkey.to_primitive().hex()
            b_name = list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
            hex_name = (
                list(utxo.output.amount.multi_asset[tokenkey].keys())[0]
                .to_primitive()
                .hex()
            )
            s["utxos"][tx_id][utxo.input.index][
                policy_id
            ] = utxo.output.amount.multi_asset[tokenkey][b_name]
            s["tokens"][policy_id] = {
                "amount": s["utxos"][tx_id][utxo.input.index][policy_id],
                "b_name": b_name,
                "hex_name": hex_name,
                "policy_id": policy_id,
                "policy_script": tokenkey,
            }
            token = s["tokens"][policy_id]
            if (policy_id + hex_name) in s["tokens_required"]:
                if token["amount"] >= s["tokens_required"][policy_id + hex_name]:
                    if not policy_id + hex_name in s["sufficient"]:
                        s["sufficient"][policy_id + hex_name] = [
                            {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                        ]
                    else:
                        s["sufficient"][policy_id + hex_name].append(
                            {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                        )
                else:
                    if not policy_id + hex_name in s["insufficient"]:
                        s["insufficient"][policy_id + hex_name] = [
                            {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                        ]
                    else:
                        s["insufficient"][policy_id + hex_name].append(
                            {"tx_id": tx_id, "index": index, "coin": token["amount"]}
                        )

# Sort sufficient/insufficient lists, check for overlaps
for suf_or_insuf in ['sufficient', 'insufficient']:
    for token, txs in s[suf_or_insuf].items():
        s[suf_or_insuf][token] = sorted(s[suf_or_insuf][token], key=lambda d: d["coin"], reverse = t if suf_or_insuf == 'insufficient' else f)
        for tx in txs:
            s["pos"][suf_or_insuf].add(json.dumps({tx["tx_id"]: tx["index"]}))
            if suf_or_insuf == 'insufficient':
                if json.dumps({tx["tx_id"]: tx["index"]}) in list(s["pos"][suf_or_insuf]):
                    s["pos"]["shared"].add(json.dumps({tx["tx_id"]: tx["index"]}))

def logs1():
    m.l("utxos", s["utxos"], t)
    m.l("tokens_required", s["tokens_required"], t)
    m.l("sufficient", s["sufficient"], t)
    m.l("insufficient", s["insufficient"], t)
    m.l("pos", s["pos"], f)
logs1()

# TODO Fix the problem with miscalculating extras on input! fml.
# create an object for utxos w/ indexes as inputs, ala {
#   tx_id: set([0, 1, 4])
# }
#
# Start with any in s["pos"]["shared"], 
# then use insufficients if there's any, 
# else use the sufficients
# 
# Track leftovers from each utxo input to cover required tokens or as change

for input in s["pos"]["shared"]:
    inp_tx = list(json.loads(input).keys())[0]
    inp_index = json.loads(input)[inp_tx]

    s['tx']['inputs'].add(json.dumps([inp_tx, inp_index]))
    
    # todo remove and create 
    s["tx_inputs"].append(TransactionInput.from_primitive([inp_tx, inp_index]))
    s['used_txs'].append([inp_tx, inp_index])

    for token, amount in s["utxos"][inp_tx][inp_index].items():
        if not token in s["balance"]["in"]:
            s["balance"]["in"][token] = 0
        s["balance"]["in"][token] += amount
        token_id = (
            "lovelace"
            if token == "lovelace"
            else token + (s["tokens"][token]["hex_name"])
        )
        if (token_id) in s["balance"]["remaining"]:
            s["balance"]["remaining"][token_id] -= amount
        else:
            if not token in s["balance"]["extra"]:
                s["balance"]["extra"][token] = amount
            else:
                s["balance"]["extra"][token] += amount
        for suf_or_insuf in ['sufficient', 'insufficient']:
            m.delist(suf_or_insuf, inp_tx, inp_index)

# iterate through balance.remaining to match best sufficient if enough, else insuf.

for token_id, amount in s["balance"]["remaining"].items():
    if amount > 0:
        for suf_or_insuf in ['sufficient', 'insufficient']:
            if token_id in s[suf_or_insuf] and len(s[suf_or_insuf][token_id]) > 0:
                for tx in s[suf_or_insuf][token_id]:
                    inp_tx = tx["tx_id"]
                    inp_index = tx["index"]
                    s['tx']['inputs'].add(json.dumps([inp_tx, inp_index]))
                    s["tx_inputs"].append(
                        TransactionInput.from_primitive([inp_tx, inp_index])
                    )
                    s['used_txs'].append([inp_tx, inp_index])
                    # m.extra(inp_tx, inp_index, token_id)
                    
                    if not token_id in s["balance"]["in"]:
                        s["balance"]["in"][token_id] = 0
                    s["balance"]["in"][token_id] += tx["coin"]
                    if suf_or_insuf == 'insufficient':
                        if (token_id) in s["balance"]["remaining"]:
                            s["balance"]["remaining"][token_id] -= amount
                        if s["balance"]["in"][token_id] >= amount:
                            break  
                    m.delist(suf_or_insuf, inp_tx, inp_index)

for token, amount in s["balance"]["in"].items():
    if (
        token in s["balance"]["out"]
        and s["balance"]["in"][token] > s["balance"]["out"][token]
    ):
        if not token in s["balance"]["extra"]:
            s["balance"]["extra"][token] = amount - s["balance"]["out"][token]
        else:
            s["balance"]["extra"][token] += amount - s["balance"]["out"][token]

s["balance"]["extra"]["lovelace"] -= s["minfee"]
if len(s["balance"]["extra"].keys()) >= 1 or s["balance"]["extra"]["lovelace"] > 0:
    if s["balance"]["extra"]["lovelace"] < s["minada"]:
        if "lovelace" in s["insufficient"] and len(s["insufficient"]["lovelace"]) > 0:
            s["insufficient"]["lovelace"].reverse()
            for tx in s["insufficient"]["lovelace"]:
                inp_tx = tx["tx_id"]
                inp_index = tx["index"]
                s['tx']['inputs'].add(json.dumps([inp_tx, inp_index]))
                s["tx_inputs"].append(
                    TransactionInput.from_primitive([inp_tx, inp_index])
                )
                s['used_txs'].append([inp_tx, inp_index])
                m.extra(inp_tx, inp_index, 'lovelace')
                for extra_token, extra_amount in s["utxos"][inp_tx][inp_index].items():
                    if extra_token != token:
                        if not extra_token in s["balance"]["extra"]:
                            s["balance"]["extra"][str(extra_token)] = extra_amount
                        else:
                            s["balance"]["extra"][str(extra_token)] += extra_amount
                s["balance"]["in"]["lovelace"] += tx["coin"]
                m.delist('insufficient', inp_tx, inp_index)
                if s["balance"]["in"]["lovelace"] >= s["minada"]:
                    break

    return_multi = {}
    for token, amount in s["balance"]["extra"].items():
        if token == "lovelace":
            return_lovelace = amount
            s['balance']['out']['lovelace'] += return_lovelace
        else:
            return_multi[bytes.fromhex(token)] = {
                bytes.fromhex(s["tokens"][token]["hex_name"]): amount
            }
            if not token in s['balance']['out']:
                s['balance']['out'][token] = amount
            else:
                s['balance']['out'][token] += amount
    s["tx_outputs"].append(
        TransactionOutput(
            address,
            Value.from_primitive(
                [return_lovelace, return_multi] if len(return_multi.keys()) > 0 else [return_lovelace]
            ),
        )
    )
    s['balance']['out']['lovelace'] += return_lovelace
    # almost done. ur slow but a genius sometimes.
    # balance the ins and outs with return for future debugging
    # if u want extra credit, make a balancing function so not to repeat.
def logs2():
    m.l("tokens", s["tokens"], t)
    m.l("pos", s["pos"], t)
    m.l("sufficient", s["sufficient"], t)
    m.l("insufficient", s["insufficient"], t)
    m.l("tx_inputs", s["tx_inputs"], t)
    m.l("tx_outputs", s["tx_outputs"], t)
    m.l("balance in", s["balance"]['in'], t)
    m.l("balance out", s["balance"]['out'], t)
    m.l("balance remaining", s["balance"]['remaining'], t)
    m.l("balance extra", s["balance"]['extra'], t)
    m.l("used_txs", s['used_txs'], t)
    m.l("tx", s['tx'], t)
logs2()

if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )

tx_body = TransactionBody(
    inputs=s["tx_inputs"], outputs=s["tx_outputs"], fee=s["minfee"]
)
signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
tx_id = str(signed_tx.id)

def logs3():
    m.l("signed_tx and id", [signed_tx, tx_id], f)
    m.l("############### Submitting transaction ###############", "", t)
    m.l("tx_body", tx_body, f)
logs3()

if s["submit"] == "true":
    context.submit_tx(signed_tx.to_cbor())
    print(tx_id)
else:
    # print(builder._fee)
    if not dev:
        print(json.dumps([tx_id, signed_tx.to_cbor()]))

# todo return proper errors
