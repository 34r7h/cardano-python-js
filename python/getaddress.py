from pycardano import Key, Address, Network, PaymentVerificationKey
# import json
# import sys
# TODO encrypt and test for production keys

# args = sys.argv[1:]
# print(type(args[0]))
# secret = args[0]
# print('secret', type(secret))

# payment_signing_key = secret
# pkey = Key.from_json(secret) 
# payment_verification_key = pkey
# print('payment_verification_key', payment_verification_key)
# pkey = open('./testpayment.vkey', 'r')
# skey = open('./teststake.vkey', 'r')

pkey = PaymentVerificationKey.load("testpayment.vkey")
skey = PaymentVerificationKey.load("teststake.vkey")

# print('payment key', pkey, skey)

base_address = Address(payment_part=pkey.hash(), staking_part=skey.hash(), network=Network.MAINNET)

print(base_address)