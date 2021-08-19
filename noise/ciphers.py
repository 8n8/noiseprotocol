import abc

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from noise.cipher import Cipher


class CryptographyCipher(Cipher, metaclass=abc.ABCMeta):
    def encrypt(self, k, n, ad, plaintext):
        return self.cipher.encrypt(nonce=self.format_nonce(n), data=plaintext, associated_data=ad)

    def decrypt(self, k, n, ad, ciphertext):
        return self.cipher.decrypt(nonce=self.format_nonce(n), data=ciphertext, associated_data=ad)

    @abc.abstractmethod
    def format_nonce(self, n):
        raise NotImplementedError


class ChaCha20Cipher(CryptographyCipher):
    @property
    def klass(self):
        return ChaCha20Poly1305

    def format_nonce(self, n):
        return b'\x00\x00\x00\x00' + n.to_bytes(length=8, byteorder='little')