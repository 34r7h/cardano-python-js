from pycardano import Address, Network

payment_signing_key = open("testpayment.skey", 'r')
payment_verification_key = open("testpayment.vkey", 'r')

base_address = Address(payment_part=payment_verification_key.hash(),
                       network=Network.MAINNET)

print(base_address)