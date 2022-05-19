from pycardano import PaymentKeyPair, StakeKeyPair

payment_key_pair = PaymentKeyPair.generate()
payment_signing_key = payment_key_pair.signing_key
payment_verification_key = payment_key_pair.verification_key

stake_key_pair = StakeKeyPair.generate()
stake_signing_key = stake_key_pair.signing_key
stake_verification_key = stake_key_pair.verification_key
payment_verification_key.save('testpayment.vkey')
payment_signing_key.save('testpayment.skey')
stake_verification_key.save('teststake.vkey')
stake_signing_key.save('teststake.skey')
keys = {
    'payment': {
        'signing': payment_key_pair.signing_key,
        'verification': payment_key_pair.verification_key
    },
    'stake': {
        'signing': stake_key_pair.signing_key,
        'verification': stake_verification_key
    }
}
print(keys)