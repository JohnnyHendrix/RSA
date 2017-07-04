from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode


class LicenseKeyGenerator:
    key = "YOUR_PRIVATE_KEY_HERE"

    def __init__(self, private_key):
        self.key = private_key

    @staticmethod
    def sign_message(message):
        global key
        rsa_key = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsa_key)
        digest = SHA512.new(message)
        sign = signer.sign(digest)
        return b64encode(sign)

    @staticmethod
    def verify_signature(signature, message_to_compare):
        global key
        rsa_key = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsa_key)
        if signer.verify(message_to_compare, b64decode(signature)):
            return True
        return False
