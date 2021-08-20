from enum import Enum

from cryptography.exceptions import InvalidTag

from noise.constants import MAX_MESSAGE_LEN
from noise.exceptions import NoiseHandshakeError, NoiseInvalidMessage
from noise.diffie_hellmans import ED25519
from noise.ciphers import ChaCha20Cipher
from noise.hashes import BLAKE2sHash
from noise.keypairs import KeyPair25519
from noise.hashes import hmac_hash
from noise.patterns import Pattern
from noise.constants import TOKEN_S, TOKEN_E, TOKEN_ES, TOKEN_SS, TOKEN_EE, TOKEN_SE
from functools import partial
from .constants import Empty
import warnings
from noise.state import HandshakeState


def hkdf(chaining_key, input_key_material, num_outputs, hmac_hash_fn):
    # Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    temp_key = hmac_hash_fn(chaining_key, input_key_material)

    # Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    output1 = hmac_hash_fn(temp_key, b"\x01")

    # Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    output2 = hmac_hash_fn(temp_key, output1 + b"\x02")

    # If num_outputs == 2 then returns the pair (output1, output2).
    if num_outputs == 2:
        return output1, output2

    # Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    output3 = hmac_hash_fn(temp_key, output2 + b"\x03")

    # Returns the triple (output1, output2, output3).
    return output1, output2, output3


class DefaultNoiseBackend:
    """
    Contains all the crypto methods endorsed by Noise Protocol specification, using Cryptography as backend
    """

    def __init__(self):
        self.diffie_hellmans = {"25519": ED25519}

        self.ciphers = {"ChaChaPoly": ChaCha20Cipher}

        self.hashes = {"BLAKE2s": BLAKE2sHash}

        self.keypairs = {"25519": KeyPair25519}

        self.hmac = hmac_hash

        self.hkdf = hkdf


class NoiseProtocol(object):
    """
    TODO: Document
    """

    def __init__(self):
        self.name = b"Noise_KK_25519_ChaChaPoly_BLAKE2s"
        self.backend = DefaultNoiseBackend()

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        self.pattern = PatternKK()

        # Preinitialized
        self.dh_fn = ED25519()
        self.hash_fn = BLAKE2sHash()
        self.hmac = partial(self.backend.hmac, algorithm=self.hash_fn.fn)
        self.hkdf = partial(self.backend.hkdf, hmac_hash_fn=self.hmac)

        # Initialized where needed
        self.cipher_class = ChaCha20Cipher
        self.keypair_class = KeyPair25519

        self.prologue = None
        self.initiator = None
        self.handshake_hash = None

        self.handshake_state = Empty()
        self.symmetric_state = Empty()
        self.cipher_state_handshake = Empty()
        self.cipher_state_encrypt = Empty()
        self.cipher_state_decrypt = Empty()

        self.keypairs = {"s": None, "e": None, "rs": None, "re": None}

    def handshake_done(self):
        if self.pattern.one_way:
            if self.initiator:
                self.cipher_state_decrypt = None
            else:
                self.cipher_state_encrypt = None
        self.handshake_hash = self.symmetric_state.get_handshake_hash()
        del self.handshake_state
        del self.symmetric_state
        del self.cipher_state_handshake
        del self.prologue
        del self.initiator
        del self.dh_fn
        del self.hash_fn
        del self.keypair_class

    def validate(self):

        if self.initiator is None:
            raise NoiseValidationError(
                "You need to set role with NoiseConnection.set_as_initiator "
                "or NoiseConnection.set_as_responder"
            )

        for keypair in self.pattern.get_required_keypairs(self.initiator):
            if self.keypairs[keypair] is None:
                raise NoiseValidationError(
                    "Keypair {} has to be set for chosen handshake pattern".format(
                        keypair
                    )
                )

        if self.keypairs["e"] is not None or self.keypairs["re"] is not None:
            warnings.warn(
                "One of ephemeral keypairs is already set. "
                "This is OK for testing, but should NEVER happen in production!"
            )

    def initialise_handshake_state(self):
        kwargs = {"initiator": self.initiator}
        if self.prologue:
            kwargs["prologue"] = self.prologue
        for keypair, value in self.keypairs.items():
            if value:
                kwargs[keypair] = value
        self.handshake_state = HandshakeState.initialize(self, **kwargs)
        self.symmetric_state = self.handshake_state.symmetric_state


class Keypair(Enum):
    STATIC = 1
    REMOTE_STATIC = 2
    EPHEMERAL = 3
    REMOTE_EPHEMERAL = 4


_keypairs = {
    Keypair.STATIC: "s",
    Keypair.REMOTE_STATIC: "rs",
    Keypair.EPHEMERAL: "e",
    Keypair.REMOTE_EPHEMERAL: "re",
}


class NoiseConnection(object):
    def __init__(self):
        self.noise_protocol = NoiseProtocol()
        self.handshake_finished = False
        self._handshake_started = False
        self._next_fn = None

    def set_as_initiator(self):
        self.noise_protocol.initiator = True
        self._next_fn = self.write_message

    def set_as_responder(self):
        self.noise_protocol.initiator = False
        self._next_fn = self.read_message

    def set_keypair_from_private_bytes(self, keypair: Keypair, private_bytes: bytes):
        self.noise_protocol.keypairs[
            _keypairs[keypair]
        ] = self.noise_protocol.dh_fn.klass.from_private_bytes(private_bytes)

    def set_keypair_from_public_bytes(self, keypair: Keypair, private_bytes: bytes):
        self.noise_protocol.keypairs[
            _keypairs[keypair]
        ] = self.noise_protocol.dh_fn.klass.from_public_bytes(private_bytes)

    def set_keypair_from_private_path(self, keypair: Keypair, path: str):
        with open(path, "rb") as fd:
            self.noise_protocol.keypairs[
                _keypairs[keypair]
            ] = self.noise_protocol.dh_fn.klass.from_private_bytes(fd.read())

    def set_keypair_from_public_path(self, keypair: Keypair, path: str):
        with open(path, "rb") as fd:
            self.noise_protocol.keypairs[
                _keypairs[keypair]
            ] = self.noise_protocol.dh_fn.klass.from_public_bytes(fd.read())

    def start_handshake(self):
        self.noise_protocol.validate()
        self.noise_protocol.initialise_handshake_state()
        self._handshake_started = True

    def write_message(self, payload: bytes = b"") -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError("Call NoiseConnection.start_handshake first")
        if self._next_fn != self.write_message:
            raise NoiseHandshakeError(
                "NoiseConnection.read_message has to be called now"
            )
        if self.handshake_finished:
            raise NoiseHandshakeError(
                "Handshake finished. NoiseConnection.encrypt should be used now"
            )
        self._next_fn = self.read_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.write_message(payload, buffer)
        if result:
            self.handshake_finished = True
        return buffer

    def read_message(self, data: bytes) -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError("Call NoiseConnection.start_handshake first")
        if self._next_fn != self.read_message:
            raise NoiseHandshakeError(
                "NoiseConnection.write_message has to be called now"
            )
        if self.handshake_finished:
            raise NoiseHandshakeError(
                "Handshake finished. NoiseConnection.decrypt should be used now"
            )
        self._next_fn = self.write_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.read_message(data, buffer)
        if result:
            self.handshake_finished = True
        return buffer

    def encrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError("Handshake not finished yet!")
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage(
                "Data must be bytes and less or equal {} bytes in length".format(
                    MAX_MESSAGE_LEN
                )
            )
        return self.noise_protocol.cipher_state_encrypt.encrypt_with_ad(None, data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError("Handshake not finished yet!")
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage(
                "Data must be bytes and less or equal {} bytes in length".format(
                    MAX_MESSAGE_LEN
                )
            )
        try:
            return self.noise_protocol.cipher_state_decrypt.decrypt_with_ad(None, data)
        except InvalidTag:
            raise NoiseInvalidMessage("Failed authentication of message")


class PatternKK(Pattern):
    def __init__(self):
        super(PatternKK, self).__init__()
        self.name = "KK"

        self.pre_messages = [[TOKEN_S], [TOKEN_S]]
        self.tokens = [[TOKEN_E, TOKEN_ES, TOKEN_SS], [TOKEN_E, TOKEN_EE, TOKEN_SE]]
