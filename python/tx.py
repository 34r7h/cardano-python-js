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
    example = []
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
