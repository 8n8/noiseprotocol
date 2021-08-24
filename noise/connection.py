from enum import Enum

from cryptography.exceptions import InvalidTag
import abc
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptography.hazmat.primitives.asymmetric import x25519
from functools import partial
import warnings
from typing import Union, List
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization


# Handshake pattern tokens
TOKEN_E = "e"
TOKEN_S = "s"
TOKEN_EE = "ee"
TOKEN_ES = "es"
TOKEN_SE = "se"
TOKEN_SS = "ss"

MAX_MESSAGE_LEN = 65535

MAX_NONCE = 2 ** 64 - 1


def from_private_bytes(private_bytes):
    if len(private_bytes) != 32:
        raise ValueError("Invalid length of private_bytes! Should be 32")
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


def get_public_bytes(key):
    try:
        key = key.public_key()
    except AttributeError:
        pass

    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def from_public_bytes(public_bytes):
    if len(public_bytes) != 32:
        raise ValueError("Invalid length of public_bytes! Should be 32")
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)


HASH_LEN = 32


def hash(x):
    digest = hashes.Hash(hashes.BLAKE2s(HASH_LEN))
    digest.update(x)
    return digest.finalize()


def hmac_hash(key, data):
    # Applies HMAC using the HASH() function.
    hmac = HMAC(key, hashes.BLAKE2s(HASH_LEN))
    hmac.update(data)
    return hmac.finalize()


DHLEN = 32


def encrypt_chacha(k, n, ad, plaintext):
    return ChaCha20Poly1305(k).encrypt(format_nonce(n), plaintext, ad)


def decrypt_chacha(k, n, ad, encrypted):
    return ChaCha20Poly1305(k).decrypt(format_nonce(n), encrypted, ad)


def format_nonce(n):
    return b"\x00\x00\x00\x00" + n.to_bytes(length=8, byteorder="little")


class CipherState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.1.

    The initialize_key() function takes additional required argument - noise_protocol.

    This class holds an instance of Cipher wrapper. It manages initialisation of underlying cipher function
    with appropriate key in initialize_key() and rekey() methods.
    """

    def __init__(self, noise_protocol):
        self.k = None
        self.n = None

    def initialize_key(self, key):
        """

        :param key: Key to set within CipherState
        """
        self.k = key
        self.n = 0

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """
        If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.

        :param ad: bytes sequence
        :param plaintext: bytes sequence
        :return: ciphertext bytes sequence
        """
        if self.n == MAX_NONCE:
            raise RuntimeError("Nonce has depleted!")

        if self.k is None:
            return plaintext

        ciphertext = encrypt_chacha(self.k, self.n, ad, plaintext)
        self.n = self.n + 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """
        If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. If an authentication
        failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.

        :param ad: bytes sequence
        :param ciphertext: bytes sequence
        :return: plaintext bytes sequence
        """
        if self.n == MAX_NONCE:
            raise RuntimeError("Nonce has depleted!")

        if self.k is None:
            return ciphertext

        plaintext = decrypt_chacha(self.k, self.n, ad, ciphertext)
        self.n = self.n + 1
        return plaintext


class SymmetricState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.2.

    The initialize_symmetric function takes different required argument - noise_protocol, which contains protocol_name.
    """

    def __init__(self):
        self.h = None
        self.ck = None
        self.noise_protocol = None
        self.cipher_state = None

    @classmethod
    def initialize_symmetric(cls, noise_protocol: "NoiseProtocol") -> "SymmetricState":
        """
        Instead of taking protocol_name as an argument, we take full NoiseProtocol object, that way we have access to
        protocol name and crypto functions

        Comments below are mostly copied from specification.

        :param noise_protocol: a valid NoiseProtocol instance
        :return: initialised SymmetricState instance
        """
        # Create SymmetricState
        instance = cls()
        instance.noise_protocol = noise_protocol

        instance.h = hash(b"Noise_KK_25519_ChaChaPoly_BLAKE2s")

        # Sets ck = h.
        instance.ck = instance.h

        # Calls InitializeKey(empty).
        instance.cipher_state = CipherState(noise_protocol)
        instance.cipher_state.initialize_key(None)
        noise_protocol.cipher_state_handshake = instance.cipher_state

        return instance

    def mix_key(self, input_key_material: bytes):
        """
        :param input_key_material:
        :return:
        """
        # Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        self.ck, temp_k = hkdf(self.ck, input_key_material, 2)

        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def mix_hash(self, data: bytes):
        """
        Sets h = HASH(h + data).

        :param data: bytes sequence
        """
        self.h = hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes):
        # Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
        self.ck, temp_h, temp_k = self.noise_protocol.hkdf(
            self.ck, input_key_material, 3
        )
        # Calls MixHash(temp_h).
        self.mix_hash(temp_h)
        # If HASHLEN is 64, then truncates temp_k to 32 bytes.
        if self.noise_protocol.hash_fn.hashlen == 64:
            temp_k = temp_k[:32]
        # Calls InitializeKey(temp_k).
        self.cipher_state.initialize_key(temp_k)

    def get_handshake_hash(self):
        return self.h

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """
        Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if
        k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.

        :param plaintext: bytes sequence
        :return: ciphertext bytes sequence
        """
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """
        Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. Note that if
        k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.

        :param ciphertext: bytes sequence
        :return: plaintext bytes sequence
        """
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        """
        Returns a pair of CipherState objects for encrypting/decrypting transport messages.

        :return: tuple (CipherState, CipherState)
        """
        # Sets temp_k1, temp_k2 = HKDF(ck, b'', 2).
        temp_k1, temp_k2 = hkdf(self.ck, b"", 2)

        # Creates two new CipherState objects c1 and c2.
        # Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
        c1, c2 = CipherState(self.noise_protocol), CipherState(self.noise_protocol)
        c1.initialize_key(temp_k1)
        c2.initialize_key(temp_k2)
        if self.noise_protocol.handshake_state.initiator:
            self.noise_protocol.cipher_state_encrypt = c1
            self.noise_protocol.cipher_state_decrypt = c2
        else:
            self.noise_protocol.cipher_state_encrypt = c2
            self.noise_protocol.cipher_state_decrypt = c1

        self.noise_protocol.handshake_done()

        # Returns the pair (c1, c2).
        return c1, c2


class HandshakeState(object):
    """
    Implemented as per Noise Protocol specification - paragraph 5.3.

    The initialize() function takes different required argument - noise_protocol, which contains handshake_pattern.
    """

    def __init__(self):
        self.noise_protocol = None
        self.symmetric_state = None
        self.initiator = None
        self.s = None
        self.e = None
        self.rs = None
        self.re = None
        self.message_patterns = None

    @classmethod
    def initialize(
        cls,
        noise_protocol: "NoiseProtocol",
        initiator: bool,
        prologue: bytes = b"",
        s: "_KeyPair" = None,
        e: "_KeyPair" = None,
        rs: "_KeyPair" = None,
        re: "_KeyPair" = None,
    ) -> "HandshakeState":
        """
        Constructor method.
        Comments below are mostly copied from specification.
        Instead of taking handshake_pattern as an argument, we take full NoiseProtocol object, that way we have access
        to protocol name and crypto functions

        :param noise_protocol: a valid NoiseProtocol instance
        :param initiator: boolean indicating the initiator or responder role
        :param prologue: byte sequence which may be zero-length, or which may contain context information that both
            parties want to confirm is identical
        :param s: local static key pair
        :param e: local ephemeral key pair
        :param rs: remote party’s static public key
        :param re: remote party’s ephemeral public key
        :return: initialized HandshakeState instance
        """
        # Create HandshakeState
        instance = cls()
        instance.noise_protocol = noise_protocol

        # Originally in specification:
        # "Derives a protocol_name byte sequence by combining the names for
        # the handshake pattern and crypto functions, as specified in Section 8."
        # Instead, we supply the NoiseProtocol to the function. The protocol name should already be validated.

        # Calls InitializeSymmetric(noise_protocol)
        instance.symmetric_state = SymmetricState.initialize_symmetric(noise_protocol)

        # Calls MixHash(prologue)
        instance.symmetric_state.mix_hash(prologue)

        # Sets the initiator, s, e, rs, and re variables to the corresponding arguments
        instance.initiator = initiator
        instance.s = s
        instance.e = e
        instance.rs = rs
        instance.re = re

        # Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified
        # public key as input (...). If both initiator and responder have pre-messages, the initiator’s public keys are
        # hashed first
        initiator_keypair_getter = (
            instance._get_local_keypair if initiator else instance._get_remote_keypair
        )
        responder_keypair_getter = (
            instance._get_remote_keypair if initiator else instance._get_local_keypair
        )
        for keypair in map(initiator_keypair_getter, [TOKEN_S]):
            instance.symmetric_state.mix_hash(get_public_bytes(keypair))
        for keypair in map(responder_keypair_getter, [TOKEN_S]):
            instance.symmetric_state.mix_hash(get_public_bytes(keypair))

        # Sets message_patterns to the message patterns from handshake_pattern
        instance.message_patterns = [
            [TOKEN_E, TOKEN_ES, TOKEN_SS],
            [TOKEN_E, TOKEN_EE, TOKEN_SE],
        ]

        return instance

    def write_message(
        self, payload: Union[bytes, bytearray], message_buffer: bytearray
    ):
        """
        Comments below are mostly copied from specification.

        :param payload: byte sequence which may be zero-length
        :param message_buffer: buffer-like object
        :return: None or result of SymmetricState.split() - tuple (CipherState, CipherState)
        """
        # Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token
        # from the message pattern
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == TOKEN_E:
                # Sets e = GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key)
                self.e = (
                    self.noise_protocol.dh_fn.generate_keypair()
                    if self.e is None
                    else self.e
                )
                message_buffer += get_public_bytes(self.e)
                self.symmetric_state.mix_hash(get_public_bytes(self.e))

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re))
                self.symmetric_state.mix_key(self.e.exchange(self.re))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.e.exchange(self.rs))
                else:
                    self.symmetric_state.mix_key(
                        self.noise_protocol.dh_fn.dh(self.s.private, self.re.public)
                    )

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(
                        self.noise_protocol.dh_fn.dh(self.s.private, self.re.public)
                    )
                else:
                    self.symmetric_state.mix_key(self.e.exchange(self.rs))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(self.s.exchange(self.rs))

            else:
                raise NotImplementedError("Pattern token: {}".format(token))

        # Appends EncryptAndHash(payload) to the buffer
        message_buffer += self.symmetric_state.encrypt_and_hash(payload)

        # If there are no more message patterns returns two new CipherState objects by calling Split()
        if len(self.message_patterns) == 0:
            return self.symmetric_state.split()

    def read_message(self, message: Union[bytes, bytearray], payload_buffer: bytearray):
        """
        Comments below are mostly copied from specification.

        :param message: byte sequence containing a Noise handshake message
        :param payload_buffer: buffer-like object
        :return: None or result of SymmetricState.split() - tuple (CipherState, CipherState)
        """
        # Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token
        # from the message pattern
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == TOKEN_E:
                # Sets re to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
                self.re = from_public_bytes(bytes(message[:DHLEN]))
                message = message[DHLEN:]
                self.symmetric_state.mix_hash(get_public_bytes(self.re))

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re)).
                self.symmetric_state.mix_key(self.e.exchange(self.re))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.e.exchange(self.rs))
                else:
                    self.symmetric_state.mix_key(self.s.exchange(self.re))

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(self.s.exchange(self.re))
                else:
                    self.symmetric_state.mix_key(self.e.exchange(self.rs))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(self.s.exchange(self.rs))

            else:
                raise NotImplementedError("Pattern token: {}".format(token))

        # Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
        payload_buffer += self.symmetric_state.decrypt_and_hash(bytes(message))

        # If there are no more message patterns returns two new CipherState objects by calling Split()
        if len(self.message_patterns) == 0:
            return self.symmetric_state.split()

    def _get_local_keypair(self, token: str) -> "KeyPair":
        keypair = getattr(
            self, token
        )  # Maybe explicitly handle exception when getting improper keypair
        if keypair is None:
            raise Exception(
                "Required keypair {} is empty!".format(token)
            )  # Maybe subclassed exception
        return keypair

    def _get_remote_keypair(self, token: str) -> "KeyPair":
        keypair = getattr(
            self, "r" + token
        )  # Maybe explicitly handle exception when getting improper keypair
        if keypair is None:
            raise Exception(
                "Required keypair {} is empty!".format("r" + token)
            )  # Maybe subclassed exception
        return keypair


def hkdf(chaining_key, input_key_material, num_outputs):
    # Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    temp_key = hmac_hash(chaining_key, input_key_material)

    # Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    output1 = hmac_hash(temp_key, b"\x01")

    # Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    output2 = hmac_hash(temp_key, output1 + b"\x02")

    # If num_outputs == 2 then returns the pair (output1, output2).
    if num_outputs == 2:
        return output1, output2

    # Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    output3 = hmac_hash(temp_key, output2 + b"\x03")

    # Returns the triple (output1, output2, output3).
    return output1, output2, output3


class NoiseProtocol(object):
    def __init__(self):
        self.name = b"Noise_KK_25519_ChaChaPoly_BLAKE2s"

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        # Preinitialized
        self.initiator = None
        self.handshake_hash = None

        self.handshake_state = None
        self.symmetric_state = None
        self.cipher_state_handshake = None
        self.cipher_state_encrypt = None
        self.cipher_state_decrypt = None

        self.keypairs = {"s": None, "e": None, "rs": None, "re": None}

    def handshake_done(self):
        self.handshake_hash = self.symmetric_state.get_handshake_hash()
        del self.handshake_state
        del self.symmetric_state
        del self.cipher_state_handshake
        del self.initiator

    def validate(self):
        if self.initiator is None:
            raise RuntimeError(
                "You need to set role with "
                "NoiseConnection.set_as_initiator or "
                "NoiseConnection.set_as_responder"
            )

        for keypair in ["s", "rs"]:
            if self.keypairs[keypair] is None:
                raise RuntimeError(
                    f"Keypair {keypair} has to be set for chosen " "handshake pattern"
                )

    def initialise_handshake_state(self):
        kwargs = {"initiator": self.initiator}
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
        self.noise_protocol.keypairs[_keypairs[keypair]] = from_private_bytes(
            private_bytes
        )

    def set_keypair_from_public_bytes(self, keypair: Keypair, private_bytes: bytes):
        self.noise_protocol.keypairs[_keypairs[keypair]] = from_public_bytes(
            private_bytes
        )

    def start_handshake(self):
        self.noise_protocol.validate()
        self.noise_protocol.initialise_handshake_state()
        self._handshake_started = True

    def write_message(self, payload: bytes = b"") -> bytearray:
        if not self._handshake_started:
            raise RuntimeError("Call NoiseConnection.start_handshake first")
        if self._next_fn != self.write_message:
            raise RuntimeError("NoiseConnection.read_message has to be called now")
        if self.handshake_finished:
            raise RuntimeError(
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
            raise RuntimeError("Call NoiseConnection.start_handshake first")
        if self._next_fn != self.read_message:
            raise RuntimeError("NoiseConnection.write_message has to be called now")
        if self.handshake_finished:
            raise RuntimeError(
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
            raise RuntimeError("Handshake not finished yet!")

        if len(data) > MAX_MESSAGE_LEN:
            raise ValueError(
                "Message must be less than or equal {} bytes in length".format(
                    MAX_MESSAGE_LEN
                )
            )

        return self.noise_protocol.cipher_state_encrypt.encrypt_with_ad(None, data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise RuntimeError("Handshake not finished yet!")

        if len(data) > MAX_MESSAGE_LEN:
            raise ValueError(
                "Message must be less than or equal {} bytes in length".format(
                    MAX_MESSAGE_LEN
                )
            )

        try:
            return self.noise_protocol.cipher_state_decrypt.decrypt_with_ad(None, data)
        except InvalidTag:
            raise RuntimeError("Failed authentication of message")
