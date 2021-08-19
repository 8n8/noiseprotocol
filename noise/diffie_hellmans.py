from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from noise.keypairs import KeyPair25519
from noise.exceptions import NoiseValueError
import abc


class DH(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def klass(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def dhlen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def generate_keypair(self) -> "KeyPair":
        raise NotImplementedError

    @abc.abstractmethod
    def dh(self, private_key, public_key) -> bytes:
        raise NotImplementedError


class ED25519(DH):
    @property
    def klass(self):
        return KeyPair25519

    @property
    def dhlen(self):
        return 32

    def generate_keypair(self) -> "KeyPair":
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair25519(
            private_key,
            public_key,
            public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(
            public_key, x25519.X25519PublicKey
        ):
            raise NoiseValueError(
                "Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances"
            )
        return private_key.exchange(public_key)
