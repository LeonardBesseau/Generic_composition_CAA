# Besseau Léonard
from abc import ABC, abstractmethod

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512, CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class Signature(ABC):
    """
    Abstract class to represent a signature primitive
    """

    @property
    def tag_size(self) -> int:
        """the size in bytes of the resulting MAC tag"""
        pass

    @abstractmethod
    def sign(self, message: bytes, key: bytes, iv: bytes) -> bytes:
        """
        generate a MAC tag of the message authenticated
        :param message: the message to authenticate
        :param key: the key to use. It must be long enough to match the expected security level of the
        MAC
        :param iv: An IV if the underling construction needs it (poly1305 for example).
        :return: a tag authenticating the message
        """
        pass

    @abstractmethod
    def verify(self, message: bytes, tag: bytes, key: bytes, iv: bytes):
        """
        Verify that a given  MAC (computed by another party) is valid.
        :param message: the message associated to the tag to verify
        :param tag: the MAC to verify
        :param key: the key used to generate the tag
        :param iv: An IV if the underling construction needs it (poly1305 for example).
        :raises ValueError: If the tag is invalid
        """
        pass


class Encryption(ABC):
    """Abstract class to represent an encryption primitive"""

    @abstractmethod
    def encrypt(self, message: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Encrypt a message with a cryptographic cipher

        :param message: the message to encrypt
        :type message: bytes

        :param key: the secret to use
        :type key: bytes

        :param iv: For counter operation, a nonce that must never be reused with the same key. For other mode,
        the initialisation vector of the cipher :type iv: bytes

        :return: the ciphertext in bytes
        """
        pass

    @abstractmethod
    def decrypt(self, cipher: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt a message encrypted with a cryptographic cipher

        :param cipher: the message to decrypt
        :type cipher: bytes

        :param key: the secret to use
        :type key: bytes

        :param iv: the IV or nonce used in the encrypt operation
        :type iv: bytes

        :return: the plaintext in bytes
        """
        pass


class AE(ABC):
    """
    Generic composition class to realize authenticated encryption
    """

    def __init__(self, encryption: Encryption, signature: Signature, key_encryption: bytes, iv_encryption: bytes,
                 key_signature: bytes,
                 iv_signature: bytes):
        """
        Initialize the AE cipher
        :param encryption: The encryption schem to use
        :param signature: The signature scheme to use
        :param key_encryption: The key used for the encryption
        :param iv_encryption: The iv to use with the encryption (Must respect requirement for encryption scheme)
        :param key_signature: The key used for the signature
        :param iv_signature: The iv to use with the signature (Must respect requirement for encryption scheme)
        """
        self.encryption = encryption
        self.signature = signature
        self.key_encryption = key_encryption
        self.iv_encryption = iv_encryption
        self.key_signature = key_signature
        self.iv_hash = iv_signature

    def Encrypt_then_MAC_encrypt(self, message: bytes) -> (bytes, bytes):
        """
        Authenticated encryption using the Encrypt-then-MAC construction
        :param message: the message to encrypt and authenticate
        :return: a ciphertext and the corresponding mac
        """
        return self._Encrypt_then_MAC_encrypt(message, self.key_encryption, self.iv_encryption, self.key_signature,
                                              self.iv_hash)

    def Encrypt_then_MAC_decrypt(self, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Authenticated decryption using the Encrypt-then-MAC construction
        :param ciphertext: a ciphertext to decrypt
        :param tag: the accompanying tag
        :return: the plaintext
        :raises ValueError if the authentication was invalid
        """
        return self._Encrypt_then_MAC_decrypt(ciphertext, tag, self.key_encryption, self.iv_encryption,
                                              self.key_signature,
                                              self.iv_hash)

    def Encrypt_and_MAC_encrypt(self, message: bytes) -> (bytes, bytes):
        """
        Authenticated encryption using the Encrypt-and-MAC construction
        :param message: the message to encrypt and authenticate
        :return: a ciphertext and the corresponding mac
        """
        return self._Encrypt_and_MAC_encrypt(message, self.key_encryption, self.iv_encryption, self.key_signature,
                                             self.iv_hash)

    def Encrypt_and_MAC_decrypt(self, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Authenticated decryption using the Encrypt-and-MAC construction
        :param ciphertext: a ciphertext to decrypt
        :param tag: the accompanying tag
        :return: the plaintext
        :raises ValueError if the authentication was invalid
        """
        return self._Encrypt_and_MAC_decrypt(ciphertext, tag, self.key_encryption, self.iv_encryption,
                                             self.key_signature,
                                             self.iv_hash)

    def MAC_then_encrypt_encrypt(self, message: bytes) -> bytes:
        """
        Authenticated encryption using the MAC-then-Encrypt construction
        :param message: the message to encrypt and authenticate
        :return: a ciphertext and the corresponding mac
        """
        return self._MAC_then_encrypt_encrypt(message, self.key_encryption, self.iv_encryption, self.key_signature,
                                              self.iv_hash)

    def MAC_then_encrypt_decrypt(self, ciphertext: bytes) -> bytes:
        """
        Authenticated decryption using the MAC-then-Encrypt construction
        :param ciphertext: a ciphertext to decrypt
        :return: the plaintext
        :raises ValueError if the authentication was invalid
        """
        return self._MAC_then_encrypt_decrypt(ciphertext, self.signature.tag_size, self.key_encryption,
                                              self.iv_encryption,
                                              self.key_signature,
                                              self.iv_hash)

    def _Encrypt_then_MAC_encrypt(self, message: bytes, encrypt_key: bytes, encrypt_iv: bytes, hash_key: bytes,
                                  hash_iv: bytes) -> (bytes, bytes):
        ciphertext = self.encryption.encrypt(message=message, key=encrypt_key, iv=encrypt_iv)
        tag = self.signature.sign(ciphertext + encrypt_iv, hash_key, hash_iv)
        return ciphertext, tag

    def _Encrypt_then_MAC_decrypt(self, ciphertext: bytes, tag: bytes, encrypt_key: bytes, encrypt_iv: bytes,
                                  hash_key: bytes, hash_iv: bytes) -> bytes:
        self.signature.verify(ciphertext + encrypt_iv, tag, hash_key, hash_iv)
        return self.encryption.decrypt(ciphertext, encrypt_key, encrypt_iv)

    def _Encrypt_and_MAC_encrypt(self, message: bytes, encrypt_key: bytes, encrypt_iv: bytes, hash_key: bytes,
                                 hash_iv: bytes) -> (bytes, bytes):
        ciphertext = self.encryption.encrypt(message, encrypt_key, encrypt_iv)
        tag = self.signature.sign(message + encrypt_iv, hash_key, hash_iv)
        return ciphertext, tag

    def _Encrypt_and_MAC_decrypt(self, ciphertext: bytes, tag: bytes, encrypt_key: bytes, encrypt_iv: bytes,
                                 hash_key: bytes, hash_iv: bytes) -> bytes:
        plaintext = self.encryption.decrypt(ciphertext, encrypt_key, encrypt_iv)
        self.signature.verify(plaintext + encrypt_iv, tag, hash_key, hash_iv)
        return plaintext

    def _MAC_then_encrypt_encrypt(self, message: bytes, encrypt_key: bytes, encrypt_iv: bytes, hash_key: bytes,
                                  hash_iv: bytes) -> bytes:
        tag = self.signature.sign(message + encrypt_iv, hash_key, hash_iv)
        ciphertext = self.encryption.encrypt(message + tag, encrypt_key, encrypt_iv)
        return ciphertext

    def _MAC_then_encrypt_decrypt(self, ciphertext: bytes, tag_len: int, encrypt_key: bytes, encrypt_iv: bytes,
                                  hash_key: bytes, hash_iv: bytes) -> bytes:
        plaintext = self.encryption.decrypt(ciphertext, encrypt_key, encrypt_iv)
        tag = plaintext[-tag_len:]
        plaintext = plaintext[:-tag_len]
        self.signature.verify(plaintext + encrypt_iv, tag, hash_key, hash_iv)
        return plaintext


class AE_AES_256_CTR_HMAC_SHA_512(AE):
    KEY_LENGTH = 32
    BLOCK_SIZE = AES.block_size

    class AES_256_CTR(Encryption):
        def encrypt(self, message: bytes, key: bytes, iv: bytes) -> bytes:
            return AES.new(key, AES.MODE_CTR, nonce=iv).encrypt(message)

        def decrypt(self, cipher: bytes, key: bytes, iv: bytes) -> bytes:
            return AES.new(key, AES.MODE_CTR, nonce=iv).decrypt(cipher)

    class HMAC_SHA512(Signature):

        @property
        def tag_size(self):
            return SHA512.digest_size

        def sign(self, message: bytes, key: bytes, iv: bytes) -> bytes:
            hmac = HMAC.new(key, digestmod=SHA512)
            hmac.update(message)
            return hmac.digest()

        def verify(self, message: bytes, tag: bytes, key: bytes, iv: bytes):
            hmac = HMAC.new(key, digestmod=SHA512)
            hmac.update(message)
            hmac.verify(tag)

    def __init__(self, key_encryption: bytes, key_signature: bytes, iv_encryption=None):
        """
        Initialize an AES_CTR_HMAC AE cipher
        :param key_encryption: the key used for the encryption. Must be 32 bytes
        :param key_signature: the key used for the signature. Must be 32 bytes
        :param iv_encryption: the IV used for the encryption. Must be at most 127 bits and must be coherent with the
        size of the message to encrypt
        """
        if len(key_encryption) != self.KEY_LENGTH:
            raise ValueError("Key size for encryption is not " + str(self.KEY_LENGTH) + " bytes")
        if len(key_signature) != self.KEY_LENGTH:
            raise ValueError("Key size for signature is not " + str(self.KEY_LENGTH) + " bytes")
        if iv_encryption is None:
            iv_encryption = get_random_bytes(AE_AES_256_CTR_HMAC_SHA_512.BLOCK_SIZE // 8 // 2)
        elif len(iv_encryption) > AE_AES_256_CTR_HMAC_SHA_512.BLOCK_SIZE-1:
            raise ValueError("Invalid IV. IV too large")
        super().__init__(self.AES_256_CTR(), self.HMAC_SHA512(), key_encryption, iv_encryption, key_signature, None)


class AE_AES_256_CBC_CMAC_AES(AE):
    KEY_LENGTH = 32
    BLOCK_SIZE = AES.block_size

    class AES_256_CBC(Encryption):

        def encrypt(self, message: bytes, key: bytes, iv: bytes) -> bytes:
            return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(message, AES.block_size))

        def decrypt(self, cipher: bytes, key: bytes, iv: bytes) -> bytes:
            return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(cipher), AES.block_size)

    class CMAC_AES(Signature):
        @property
        def tag_size(self):
            return AES.block_size

        def sign(self, message: bytes, key: bytes, iv: bytes) -> bytes:
            cmac = CMAC.new(key, ciphermod=AES)
            cmac.update(message)
            return cmac.digest()

        def verify(self, message: bytes, tag: bytes, key: bytes, iv: bytes):
            cmac = CMAC.new(key, ciphermod=AES)
            cmac.update(message)
            cmac.verify(tag)

    def __init__(self, key_encryption: bytes, key_signature: bytes, iv_encryption: bytes = None):
        """
        Initialize an AES_CBC_CMAC AE cipher
        :param key_encryption: the key used for the encryption. Must be 32 bytes
        :param key_signature: the key used for the signature. Must be 32 bytes
        :param iv_encryption: the IV used for the encryption. Must be  128 bits long and must be coherent with the
        size of the message to encrypt
        """
        if len(key_encryption) != self.KEY_LENGTH:
            raise ValueError("Key size for encryption is not " + str(self.KEY_LENGTH) + " bytes")
        if len(key_signature) != self.KEY_LENGTH:
            raise ValueError("Key size for signature is not " + str(self.KEY_LENGTH) + " bytes")
        if iv_encryption is None:
            iv_encryption = get_random_bytes(128 // 8)
        super().__init__(self.AES_256_CBC(), self.CMAC_AES(), key_encryption, iv_encryption, key_signature, None)
