from pycardano import PaymentKeyPair, StakeKeyPair

payment_key_pair = PaymentKeyPair.generate()
stake_key_pair = StakeKeyPair.generate()

payment_signing_key = payment_key_pair.signing_key
payment_verification_key = payment_key_pair.verification_key
stake_signing_key = stake_key_pair.signing_key
stake_verification_key = stake_key_pair.verification_key

keys = {
    "payment": {
        "signing": payment_key_pair.signing_key,
        "verification": payment_key_pair.verification_key
    },
    "stake": {
        "signing": stake_key_pair.signing_key,
        "verification": stake_verification_key
    }
}
print(keys) 