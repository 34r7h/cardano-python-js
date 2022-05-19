from pycardano import Address, Network
import sys
# payment_signing_key = open("testpayment.skey", 'r')
# payment_verification_key = open("testpayment.vkey", 'r')
args = list(sys.argv[1:]) 
print(args)
# base_address = Address(payment_part=payment_verification_key.hash(),
#                        network=Network.MAINNET)

# print(base_address)