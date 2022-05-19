from pycardano import Address, Network
import json
import sys

args = list(sys.argv[1:])
secret = json.loads(args[0])
print(secret)

payment_signing_key = secret
payment_verification_key = open("testpayment.vkey", 'r')

# base_address = Address(payment_part=payment_verification_key.hash(),
#                        network=Network.MAINNET)

# print(base_address)