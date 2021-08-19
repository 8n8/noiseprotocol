from noise.ciphers import ChaCha20Cipher
from noise.diffie_hellmans import ED25519
from noise.hashes import hmac_hash, BLAKE2sHash
from noise.keypairs import KeyPair25519
from noise.hash import hkdf


class DefaultNoiseBackend:
    """
    Contains all the crypto methods endorsed by Noise Protocol specification, using Cryptography as backend
    """

    def __init__(self):
        super(DefaultNoiseBackend, self).__init__()

        self.diffie_hellmans = {
            '25519': ED25519
        }

        self.ciphers = {
            'ChaChaPoly': ChaCha20Cipher
        }

        self.hashes = {
            'BLAKE2s': BLAKE2sHash
        }

        self.keypairs = {
            '25519': KeyPair25519
        }

        self.hmac = hmac_hash

        self.hkdf = hkdf
