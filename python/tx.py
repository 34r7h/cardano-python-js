from cmath import log
from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

t = True
f = False
dev = t

example = [
    "{\"payment\":{\"signing\":{\"type\":\"PaymentSigningKeyShelley_ed25519\",\"description\":\"PaymentSigningKeyShelley_ed25519\",\"cborHex\":\"58202c2066ed218b7c9308526077bcf1e3a0a81a4da99767ce0746093f6e09272e9c\"},\"verification\":{\"type\":\"PaymentVerificationKeyShelley_ed25519\",\"description\":\"PaymentVerificationKeyShelley_ed25519\",\"cborHex\":\"58207533eaba8c8636c0a4bc62aeebbe44a9490aea888aca9ebf5123b768b85790ab\"}},\"stake\":{\"signing\":{\"type\":\"StakeSigningKeyShelley_ed25519\",\"description\":\"StakeSigningKeyShelley_ed25519\",\"cborHex\":\"5820e59e3e2687eb9f77f3c4ab6b08678c0c358b87652e4b7f5a29b4882a17036530\"},\"verification\":{\"type\":\"StakeVerificationKeyShelley_ed25519\",\"description\":\"StakeVerificationKeyShelley_ed25519\",\"cborHex\":\"5820d3028f37465a91da25385e6b28eeaa3fc684bb37c2c245ad0ff943991a4d1f33\"}}}","{\"address\":\"addr1q9nzv2662ey4kkx96makz82q99wwzehs2uzrt9wwyttq723xkkkcpe0xgfzya3g0jzz825fyfzwm7melppsjr3uw72qs7am8ys\",\"outputs\":[{\"address\":\"addr1qxftfc2s95ss6uz242vxzlw3uu6njuzdp6gldjqfjyzyz6hl0zvkw9l9v69763fl3day46p9lzt2vr66s937emalexeqljy59n\",\"tokens\":[{\"index\":\"0\",\"quantity\":\"2651897\",\"unit\":\"lovelace\"},{\"asset\":\"2d93c679676ff59f092b448c942212312267a67eae63f57b4905133177746620636f696e\",\"policy_id\":\"2d93c679676ff59f092b448c942212312267a67eae63f57b49051331\",\"asset_name\":\"77746620636f696e\",\"fingerprint\":\"asset19qcq3zqma4zv3df2hc2fpcuxdzxxacfv7erser\",\"quantity\":\"1\",\"initial_mint_tx_hash\":\"28928ae3fa3c3bdd92ee95e8002548950d7cd62ecd128df38e3049b1032cab1b\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":{\"name\":\"wtf coin\",\"files\":[{\"src\":\"ipfs://QmWkAiVh7DnNAS4Y8TzYDVVxawtBjQEHde1jfGJKBnBtzY\",\"name\":\"screen_shot_2022-06-28_at_16.53.45.png\",\"mediaType\":\"image/png\"},{\"src\":\"ipfs://QmXXEtathaKw48fC5tCL1Fg44JmJc3QwxR813DvCskR3F1\",\"name\":\"5vwsee.jpeg\",\"mediaType\":\"image/jpeg\"}],\"minted_on\":\"11/07/2022 17:11:39\"},\"metadata\":\"\",\"hexname\":\"wtf coin\",\"unit\":\"2d93c679676ff59f092b448c942212312267a67eae63f57b4905133177746620636f696e\",\"index\":\"1\",\"name\":\"wtf coin\"},{\"asset\":\"581513d0cdb8a1cd3753a5fd4cf9c2931453253aeb5cf252667ee7244147415045706f6f6c62657461\",\"policy_id\":\"581513d0cdb8a1cd3753a5fd4cf9c2931453253aeb5cf252667ee724\",\"asset_name\":\"4147415045706f6f6c62657461\",\"fingerprint\":\"asset1nelpqtqthu6058t0h9nqn4zf08qkqpwzmv9gkg\",\"quantity\":\"18000\",\"initial_mint_tx_hash\":\"e738ed4a68e9946f99ad83fda9bfa7ee51660186bf7a4c8870098d7df98d81df\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":\"\",\"metadata\":\"\",\"hexname\":\"AGAPEpoolbeta\",\"unit\":\"581513d0cdb8a1cd3753a5fd4cf9c2931453253aeb5cf252667ee7244147415045706f6f6c62657461\",\"index\":\"2\",\"name\":\"AGAPEpoolbeta\"},{\"asset\":\"ae44f6f2bf702326b8b02b5d902458b99c47de929a7d7922eac4d6be58796d626f6c50726f746f7479706531\",\"policy_id\":\"ae44f6f2bf702326b8b02b5d902458b99c47de929a7d7922eac4d6be\",\"asset_name\":\"58796d626f6c50726f746f7479706531\",\"fingerprint\":\"asset1al3r3f2f2xegj7h37sjnr8h7j9mtam0fve2srs\",\"quantity\":\"2\",\"initial_mint_tx_hash\":\"faf5315e64676e36aef7e0f0bd5ef9dad55683784f6ac2857d967db2637ef5a4\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":\"\",\"metadata\":\"\",\"hexname\":\"XymbolPrototype1\",\"unit\":\"ae44f6f2bf702326b8b02b5d902458b99c47de929a7d7922eac4d6be58796d626f6c50726f746f7479706531\",\"index\":\"3\",\"name\":\"XymbolPrototype1\"},{\"asset\":\"cf0718f10faa46e686ec2fbfbde8ef99a7c75ae28026db09e06bb8616c6f76655f6561727468\",\"policy_id\":\"cf0718f10faa46e686ec2fbfbde8ef99a7c75ae28026db09e06bb861\",\"asset_name\":\"6c6f76655f6561727468\",\"fingerprint\":\"asset15u5dd842ar9w8ykpmf4l738ucpsxxg9hwhggqq\",\"quantity\":\"1\",\"initial_mint_tx_hash\":\"c20e3d7c168a3e894587f1cd91daed316031d8fe139babef34e09737e49d5ef1\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":{\"name\":\"love_earth\",\"image\":\"ipfs://undefined\",\"id\":\"c94cdd2147898c6bfb65e57fd8b221b7df129c7d3313a8ab03da80fefe069daa\",\"Set\":\"XMBLs (1 of 1)\",\"size\":\"362596\",\"files\":[{\"src\":\"ipfs://undefined\",\"name\":\"Screenshot from 2021-11-10 17-51-42.png\",\"mediaType\":\"image/png\"}],\"Artist\":\"Glootie\",\"Rarity\":\"Tier 1 (1 of 1)\",\"Creator\":\"Glootie\",\"Discord\":\"https://discord.gg/446844338538938378\",\"Twitter\":\"https://twitter/i34r7h\",\"filehash\":\"da26dfec4db1dec654ec1f42b7af1e0de7962d6383fa5639c5c771e0e08c6335\",\"copyright\":\"Copyright 2021 no one ever\",\"imagehash\":\"0bdd37e3284125564902d5a03117942ba0c2290d2f1b270fd533b856a930e2c7\",\"mediaType\":\"image/png\",\"Collection\":\"XMBL tests\",\"xymboltoken\":\"c94cdd2147898c6bfb65e57fd8b221b7df129c7d3313a8ab03da80fefe069daa\"},\"metadata\":\"\",\"hexname\":\"love_earth\",\"unit\":\"cf0718f10faa46e686ec2fbfbde8ef99a7c75ae28026db09e06bb8616c6f76655f6561727468\",\"index\":\"4\",\"name\":\"love_earth\"},{\"asset\":\"da2bd6118fffc30168a1bc19e288244bc25e49892269aca57753292554616e676f\",\"policy_id\":\"da2bd6118fffc30168a1bc19e288244bc25e49892269aca577532925\",\"asset_name\":\"54616e676f\",\"fingerprint\":\"asset1s5cmudfq0fx0xupps2d09s4rt0ae8zxm2nla7m\",\"quantity\":\"1000000\",\"initial_mint_tx_hash\":\"8d858912c0f3949cfc441744ba74ad38ead66a4d9223138ae580d4486de07846\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":\"\",\"metadata\":\"\",\"hexname\":\"Tango\",\"unit\":\"da2bd6118fffc30168a1bc19e288244bc25e49892269aca57753292554616e676f\",\"index\":\"5\",\"name\":\"Tango\"},{\"asset\":\"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d61\",\"policy_id\":\"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d\",\"asset_name\":\"61\",\"fingerprint\":\"asset1vfgfqwyz7anytq2z3n5qpksg4p49vk74zk0njf\",\"quantity\":\"1\",\"initial_mint_tx_hash\":\"a2065d2947497e0c5342928666fb23ac9df52ae8fd5d80196f9f318411c35259\",\"mint_or_burn_count\":\"1\",\"onchain_metadata\":{\"name\":\"a\",\"minted_on\":\"29/06/2022 18:54:26\"},\"metadata\":\"\",\"hexname\":\"a\",\"unit\":\"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d61\",\"index\":\"6\",\"name\":\"a\"}]}],\"submit\":\"true\"}","mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza",
]
args = sys.argv[1:] or example

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
return_address = Address.from_primitive(jsondata["address"])

utxos_from_bf = context.utxos(str(return_address))


class Methods:
    def l(self, l, d, s):  # pretty and informative logging
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


state = {
    "minada": 2000000,
    "minfee": 200000,
    "sendall": f,  # TODO put option on front end
    "submit": jsondata["submit"],
    "required": {"lovelace": 200000},  # default with minfee
    "total_in": {},
    "return": {},
    "tokens": {},
    "tx_inputs": [],
    "tx_outputs": [],
}

s = state
d = jsondata
m = Methods()
# iterate through tx output requests
for output in d["outputs"]:
    lovelace = 0
    multi = {}
    # Set required and prep tx output
    for token in output["tokens"]:
        m.l("output token", token, t)
        # set required
        if not token["unit"][0:56] in s["required"]:
            s["required"][token["unit"][0:56]] = int(token["quantity"])
        else:
            s["required"][token["unit"][0:56]] += int(token["quantity"])
        # prepare output
        if token["unit"] == "lovelace":
            lovelace = int(token["quantity"])
        else:
            # name = bytes.fromhex(token['unit'][57:-1])
            m.l("name", token["unit"][57:-1], t)
            multi[bytes.fromhex(token["unit"][0:56])] = {bytes(token['hexname'], 'utf-8'): int(token["quantity"])}
    # Create tx output
    s["tx_outputs"].append(
        TransactionOutput(
            Address.decode(output["address"]),
            Value.from_primitive(
                [lovelace, multi] if len(multi.keys()) > 0 else [lovelace]
            ),
        )
    )
# Iterate through available utxos, set inputs, set total_in
for utxo in utxos_from_bf:
    m.l("utxo", utxo, t)
    tx_id = str(utxo.input.transaction_id)
    coin = utxo.output.amount.coin
    index = utxo.input.index
    # Set input
    s["tx_inputs"].append(TransactionInput.from_primitive([tx_id, index]))
    # set total_in
    if not "lovelace" in s["total_in"]:
        s["total_in"]["lovelace"] = coin
    else:
        s["total_in"]["lovelace"] += coin
    if len(utxo.output.amount.multi_asset.keys()) > 0:
        for token_key, token in utxo.output.amount.multi_asset.items():
            name = list(token.keys())[0].to_primitive().hex()
            amount = token[list(token.keys())[0]]
            policy_id = token_key.to_primitive().hex()
            s["tokens"][policy_id] = {"name": bytes.fromhex(name)}
            if not policy_id in s["total_in"]:
                s["total_in"][policy_id] = amount
            else:
                s["total_in"][policy_id] += amount
# Find difference of total_in from required
for token, qty in s["total_in"].items():
    if token in s["required"]:
        s["return"][token] = qty - s["required"][token]
    else:
        s["return"][token] = qty


# Create return output from difference
return_multi = {}
return_lovelace = 0
for token, qty in s["return"].items():
    if token == "lovelace":
        return_lovelace += qty
    else:
        return_multi[bytes.fromhex(token)] = {s["tokens"][token]["name"]: qty}

if return_lovelace > s["minada"]:
    s["tx_outputs"].append(
        TransactionOutput(
            return_address,
            Value.from_primitive(
                [return_lovelace, return_multi]
                if len(return_multi.keys()) > 0
                else [return_lovelace]
            ),
        )
    )
for log in ["required", "total_in", "tx_inputs", "tx_outputs"]:
    m.l(log, s[log], t)

# Metadata
if "metadata" in jsondata:
    auxiliary_data = AuxiliaryData(
        AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
    )
# Create Raw Tx
tx_body = TransactionBody(
    inputs=s["tx_inputs"], outputs=s["tx_outputs"], fee=s["minfee"]
)
# Sign tx and get deterministic tx ID
signature = sk.sign(tx_body.hash())
vk_witnesses = [VerificationKeyWitness(vk, signature)]
signed_tx = Transaction(tx_body, TransactionWitnessSet(vkey_witnesses=vk_witnesses))
tx_id = str(signed_tx.id)
# Submit or return signed_tx
if s["submit"] == "true":
    context.submit_tx(signed_tx.to_cbor())
    print(tx_id)
else:
    # print(builder._fee)
    if not dev:
        print(json.dumps([tx_id, signed_tx.to_cbor()]))

# todo return proper errors
# test metadata and check tx fee cost increase
# add minting to this script
