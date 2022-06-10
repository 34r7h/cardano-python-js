from pycardano import BlockFrostChainContext, Network, PaymentSigningKey, PaymentVerificationKey, Address, TransactionBuilder, TransactionOutput, Value
import json
import sys

print('\n i will create a tx if you supply purpose and relevant checks along with moneies. \n')

# args = sys.argv[1:]
# secret = args[0]
# jsonsecret = json.loads(secret)

# pkey  = jsonsecret['payment']['verification']['cborHex']
# skey  = jsonsecret['stake']['verification']['cborHex']

network = Network.MAINNET
context = BlockFrostChainContext("mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza", network)

sk = PaymentSigningKey.from_cbor('5820d5eab6c1c4986a39a230537e8a6eb11f49dbb8a7bd8e368967eb84bebfb7e488')
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive('addr1qytqt3v9ej3kzefxcy8f59h9atf2knracnj5snkgtaea6p4r8g3mu652945v3gldw7v88dn5lrfudx0un540ak9qt2kqhfjl0d')

builder = TransactionBuilder(context)
builder.add_input_address(address)
utxos = context.utxos(str(address))
print('\nutxos',utxos)
if len(utxos) == 0:
    print('No utxos available on this address')
elif len(utxos) == 1:
    print('add raw input')
    builder.add_input(utxos[0])
else:
    print('use builder\n')


builder.add_output(
    TransactionOutput(
        Address.from_primitive(
            "addr1qyady0evsaxqsfmz0z8rvmq62fmuas5w8n4m8z6qcm4wrt3e8dlsen8n464ucw69acfgdxgguscgfl5we3rwts4s57ashysyee"
        ),
        Value.from_primitive(
            [
                1000000,
            ]
        ),
    )
)
signed_tx = builder.build_and_sign([sk], change_address=address)
tx_id = str(signed_tx.id)

# todo remove submit to it's own function
context.submit_tx(signed_tx.to_cbor())
print('\nTX Details\n', builder, '\n', signed_tx, tx_id)