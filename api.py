from pycardano import *
network = Network.MAINNET
psk = PaymentSigningKey.load("payment.skey")
# Assume there is a stake.skey file sitting in current directory
ssk = StakeSigningKey.load("stake.skey")

pvk = PaymentVerificationKey.from_signing_key(psk)
svk = StakeVerificationKey.from_signing_key(ssk)

# payment_key_pair = PaymentKeyPair.generate()
# payment_signing_key = payment_key_pair.signing_key
# payment_verification_key = payment_key_pair.verification_key

# stake_key_pair = StakeKeyPair.generate()
# stake_signing_key = stake_key_pair.signing_key
# stake_verification_key = stake_key_pair.verification_key

# Save
# payment_signing_key.save("payment.skey")
# payment_verification_key.save("payment.vkey")
# stake_signing_key.save("stake.skey")
# stake_verification_key.save("stake.vkey")

# Load
# payment_signing_key = payment_signing_key.load("payment.skey")
# payment_verification_key = payment_verification_key.load("payment.vkey")
# stake_signing_key = payment_signing_key.load("stake.skey")
# stake_verification_key = payment_verification_key.load("stake.vkey")

# Derive an address from payment verification key and stake verification key
address = Address(pvk.hash(), svk.hash(), network)

print(address)
