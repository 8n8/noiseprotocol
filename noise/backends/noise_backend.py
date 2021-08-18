from noise.exceptions import NoiseProtocolNameError
from noise.functions.hash import hkdf
from noise.patterns import PatternKK
from noise.backends.default.diffie_hellmans import ED25519
from noise.backends.default.ciphers import ChaCha20Cipher
from noise.backends.default.hashes import BLAKE2sHash
from noise.backends.default.keypairs import KeyPair25519


class NoiseBackend:
    """
    Base for creating backends.
    Implementing classes must define supported crypto methods in appropriate dict (diffie_hellmans, ciphers, etc.)
    HMAC function must be defined as well.

    Dicts use convention for keys - they must match the string that occurs in Noise Protocol name.
    """
    def __init__(self):

        self.diffie_hellmans = {}
        self.ciphers = {}
        self.hashes = {}
        self.keypairs = {}
        self.hmac = None

        self.hkdf = hkdf

    def map_protocol_name_to_crypto(self, unpacked_name):
        return {
            'pattern': PatternKK,
            'dh': ED25519,
            'cipher': ChaCha20Cipher,
            'hash': BLAKE2sHash,
            'keypair': KeyPair25519
        }
