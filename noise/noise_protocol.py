import warnings
from functools import partial
from typing import Tuple

from noise.exceptions import NoiseProtocolNameError, NoisePSKError, NoiseValidationError
from noise.state import HandshakeState
from .constants import MAX_PROTOCOL_NAME_LEN, Empty

from noise.patterns import PatternKK
from noise.backends.default.diffie_hellmans import ED25519
from noise.backends.default.ciphers import ChaCha20Cipher
from noise.backends.default.hashes import BLAKE2sHash
from noise.backends.default.keypairs import KeyPair25519


class NoiseProtocol(object):
    """
    TODO: Document
    """
    def __init__(self, protocol_name: bytes, backend: 'NoiseBackend'):
        self.name = protocol_name
        self.backend = backend

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        self.pattern = PatternKK()

        # Preinitialized
        self.dh_fn = ED25519()
        self.hash_fn = BLAKE2sHash()
        self.hmac = partial(backend.hmac, algorithm=self.hash_fn.fn)
        self.hkdf = partial(backend.hkdf, hmac_hash_fn=self.hmac)

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

        self.keypairs = {'s': None, 'e': None, 'rs': None, 're': None}

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
            raise NoiseValidationError('You need to set role with NoiseConnection.set_as_initiator '
                                       'or NoiseConnection.set_as_responder')

        for keypair in self.pattern.get_required_keypairs(self.initiator):
            if self.keypairs[keypair] is None:
                raise NoiseValidationError('Keypair {} has to be set for chosen handshake pattern'.format(keypair))

        if self.keypairs['e'] is not None or self.keypairs['re'] is not None:
            warnings.warn('One of ephemeral keypairs is already set. '
                          'This is OK for testing, but should NEVER happen in production!')

    def initialise_handshake_state(self):
        kwargs = {'initiator': self.initiator}
        if self.prologue:
            kwargs['prologue'] = self.prologue
        for keypair, value in self.keypairs.items():
            if value:
                kwargs[keypair] = value
        self.handshake_state = HandshakeState.initialize(self, **kwargs)
        self.symmetric_state = self.handshake_state.symmetric_state
