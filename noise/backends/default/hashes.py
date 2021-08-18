import abc
from functools import partial

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

from noise.functions.hash import Hash

cryptography_backend = default_backend()


class CryptographyHash(Hash, metaclass=abc.ABCMeta):
    def hash(self, data):
        digest = hashes.Hash(self.fn(), cryptography_backend)
        digest.update(data)
        return digest.finalize()


class BLAKE2sHash(CryptographyHash):
    @property
    def fn(self):
        return partial(hashes.BLAKE2s, digest_size=self.hashlen)

    @property
    def hashlen(self):
        return 32

    @property
    def blocklen(self):
        return 64


def hmac_hash(key, data, algorithm):
    # Applies HMAC using the HASH() function.
    hmac = HMAC(key=key, algorithm=algorithm(), backend=cryptography_backend)
    hmac.update(data=data)
    return hmac.finalize()
