from pycardano import Key, Address, Network, PaymentVerificationKey, StakeVerificationKey, PaymentKeyPair, StakeKeyPair
import json
import sys
# TODO encrypt and test for production keys


args = sys.argv[1:]
secret = args[0]
jsonsecret = json.loads(secret)

pkey  = jsonsecret['payment']['verification']['cborHex']
skey  = jsonsecret['stake']['verification']['cborHex']

base_address = Address(payment_part=PaymentVerificationKey.from_cbor(pkey).hash(), staking_part=StakeVerificationKey.from_cbor(skey).hash(), network=Network.MAINNET)

print(base_address)
