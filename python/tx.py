from cmath import log
from pycardano import *
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, List

t = True
f = False
dev = f


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

    def calc_fee(self, tx):
        return len(str(tx).encode("utf-8"))

    def e(self, m):
        print(m)
        sys.exit(m)


m = Methods()
try:
    example = [
        '{"payment":{"signing":{"type":"PaymentSigningKeyShelley_ed25519","description":"PaymentSigningKeyShelley_ed25519","cborHex":"582099391d63bc2625806b84102aaa01b0e440d4c2eb2899c47ef6b3d46ec05c002f"},"verification":{"type":"PaymentVerificationKeyShelley_ed25519","description":"PaymentVerificationKeyShelley_ed25519","cborHex":"5820b0f8b12bfcf37f8e6867c4888bebebedab16ffc6bf877d71694c8458977c72ea"}},"stake":{"signing":{"type":"StakeSigningKeyShelley_ed25519","description":"StakeSigningKeyShelley_ed25519","cborHex":"5820e5b36759e4ae59c5941d1d81b6ac84307ed199070b55adb3bda8288ce1b7b119"},"verification":{"type":"StakeVerificationKeyShelley_ed25519","description":"StakeVerificationKeyShelley_ed25519","cborHex":"5820de68fab7aa37377115229d663098f7148f110106711810f7b8519d320a9993cd"}}}',
        '{"address":"addr1qx877x8vz3d76xxj9cyfqnrtkp0d97twp3r4szwtln05h0v79yjulpsd0fpfrs6zzg04pc5hn7w0kugx7t0wwq5hn5cqe3c3ew","outputs":[{"address":"addr1q89dlndels95mhcqjqxhk3qz4g4fhr82jntncrh2yj2jwaf89hyfl3dr9nhcj5xgvdga565qgaukf8hsg27fe9wm89astmfjc9","tokens":[{"unit":"lovelace","quantity":"10821086","index":"0"},{"unit":"16d657be5b781fd5c7d13d5358c8be7c15509739ae15d5b3b5e6f06a537562736964652050617276617469","quantity":"1","index":"1"},{"unit":"2d93c679676ff59f092b448c942212312267a67eae63f57b4905133177746620636f696e","quantity":"1","index":"2"},{"unit":"4cb85b57144cd8cfd7fc58e14af07ca0db0d31184e37035ad74eb6fe776879206e6f74","quantity":"1","index":"3"},{"unit":"581513d0cdb8a1cd3753a5fd4cf9c2931453253aeb5cf252667ee7244147415045706f6f6c62657461","quantity":"19670","index":"4"},{"unit":"92952ee27042c68cd5a807d686dd75010115dfe6feab2c898f0fde1458796d626f6c","quantity":"9","index":"5"},{"unit":"ae44f6f2bf702326b8b02b5d902458b99c47de929a7d7922eac4d6be58796d626f6c50726f746f7479706531","quantity":"2","index":"6"},{"unit":"cf0718f10faa46e686ec2fbfbde8ef99a7c75ae28026db09e06bb8616c6f76655f6561727468","quantity":"1","index":"7"},{"unit":"da2bd6118fffc30168a1bc19e288244bc25e49892269aca57753292554616e676f","quantity":"1000000","index":"8"},{"unit":"ec2d31189092312fc8aebdf0f2551bc4de9f1e570620be902f15433d61","quantity":"1","index":"9"},{"unit":"f6196e5384f1e40723d678fc42e6926f4bb35df08b36e57db17b0254776879206e6f74","quantity":"1","index":"10"}]}],"submit":"true"}',
        "mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza",
    ]
    args = sys.argv[1:] or example
    if len(args) <= 2:
        m.e("Arguments have no data.")

    if len(args) > 2:
        secret = args[0]
        data = args[1]
        bf = args[2]

        jsonsecret = json.loads(secret)
        jsondata = json.loads(data)

        if not "payment" in jsonsecret or not "stake" in jsonsecret:
            m.e("Unable to load keys")

        pkey = jsonsecret["payment"]["signing"]["cborHex"]
        vkey = jsonsecret["payment"]["verification"]["cborHex"]

    network = Network.MAINNET

    context = BlockFrostChainContext(bf, network)
    if context.api.health().is_healthy != True:
        m.e("Problem connecting with BlockFrost.")

    sk = PaymentSigningKey.from_cbor(pkey)
    vk = PaymentVerificationKey.from_signing_key(sk)

    return_address = Address.from_primitive(jsondata["address"])
    utxos_from_bf = context.utxos(str(return_address))

    state = {
        "minada": 2000000,
        "minfee": int(jsondata["txfee"]) or 300000,
        "sendall": f,  # TODO put option on front end
        "submit": jsondata["submit"],
        "required": {"lovelace": int(jsondata["txfee"]) or 300000},  # default with minfee
        "total_in": {},
        "return": {},
        "tokens": {},
        "tx_inputs": [],
        "tx_outputs": [],
    }

    s = state
    d = jsondata
    # iterate through tx output requests
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
    m.l("tokens", s["tokens"], t)
    for output in d["outputs"]:
        lovelace = 0
        multi = {}
        # Set required and prep tx output
        for token in output["tokens"]:
            token_policy = token["unit"][0:56]
            m.l("output token", token, t)

            # set required
            if not token_policy in s["required"]:
                s["required"][token_policy] = int(token["quantity"])
            else:
                s["required"][token_policy] += int(token["quantity"])
            # prepare output
            if token["unit"] == "lovelace":
                lovelace = int(token["quantity"])
            else:
                multi[bytes.fromhex(token_policy)] = {
                    s["tokens"][token_policy]["name"]: int(token["quantity"])
                }
        # Create tx output
        s["tx_outputs"].append(
            TransactionOutput(
                Address.decode(output["address"]),
                Value.from_primitive(
                    [lovelace, multi] if len(multi.keys()) > 0 else [lovelace]
                ),
            )
        )

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
    for log in ["required", "total_in", "tx_inputs", "tx_outputs", "tokens"]:
        m.l(log, s[log], t)

    # Metadata
    if "metadata" in jsondata:
        auxiliary_data = AuxiliaryData(
            AlonzoMetadata(metadata=Metadata({721: jsondata["metadata"]}))
        )
    # Create Raw Tx

    # Subtract minfee
    # total_fee_subtracted = 0
    # for output in s['tx_outputs']:
    #     m.l('tx_output', output, t)
    #     if output.amount.coin - s['minfee'] >= s['minada'] - total_fee_subtracted:
    #         output.amount.coin -= s['minfee']
    #         break
    #     else:
    #         total_fee_subtracted += output.amount.coin - s['minada']
    #         output.amount.coin = s['minada']
    #         if total_fee_subtracted >= s['minfee']:
    #             output.amount.coin += total_fee_subtracted - s['minfee']
    #             break
    #     m.l('total_fee_subtracted', total_fee_subtracted, t)
    # m.l('tx_outputs', s['tx_outputs'], t)
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
except:
    error = sys.exc_info()[1]
    print(error)
    m.e([sys.exc_info()[0].__name__, error])
