from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from noise.exceptions import NoiseValueError
import abc


class KeyPair(metaclass=abc.ABCMeta):
    def __init__(self, private=None, public=None, public_bytes=None):
        self.private = private
        self.public = public
        self.public_bytes = public_bytes

    @classmethod
    @abc.abstractmethod
    def from_private_bytes(cls, private_bytes):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_public_bytes(cls, public_bytes):
        raise NotImplementedError


class KeyPair25519(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError("Invalid length of private_bytes! Should be 32")
        private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(
            private=private,
            public=public,
            public_bytes=public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 32:
            raise NoiseValueError("Invalid length of public_bytes! Should be 32")
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return cls(
            public=public,
            public_bytes=public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )
