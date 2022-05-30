from pycardano import Key, Address, Network, PaymentVerificationKey, StakeVerificationKey
import json
import sys
# TODO encrypt and test for production keys

args = sys.argv[1:]
# print(type(args[0]))
secret = args[0]
jsonsecret = json.loads(secret)
print(jsonsecret, type(jsonsecret))
pkey  = jsonsecret['payment']
skey  = jsonsecret['stake']
pkeyhash = PaymentVerificationKey.hash(pkey)
skeyhash = StakeVerificationKey.hash(skey)
print(pkeyhash, skeyhash)
# payment_signing_key = secret
# pkey = Key.from_json(secret) 
# payment_verification_key = pkey
# print('payment_verification_key', payment_verification_key)
# pkey = open('./testpayment.vkey', 'r')
# skey = open('./teststake.vkey', 'r')

# pkey = PaymentVerificationKey.load("testpayment.vkey")
# skey = PaymentVerificationKey.load("teststake.vkey")

# print('payment key', pkey, skey)

base_address = Address(payment_part=PaymentVerificationKey.from_cbor(pkeyhash), staking_part=StakeVerificationKey.from_cbor(skeyhash), network=Network.MAINNET)

print(base_address)
print('keys', Key(jsonsecret['payment']).from_json())