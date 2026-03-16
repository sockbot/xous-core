# -*- coding: utf-8 -*-

# AES-GCM-SIV wrapper providing backward-compatible API around the
# cryptography library's AESGCMSIV implementation (RFC 8452).
#
# This replaces the previous vendored reference implementation from
# https://github.com/bjornedstrom/aes-gcm-siv-py which depended on
# pyaesni (now bit-rotting). See https://github.com/betrusted-io/xous-core/issues/547
#
# The wrapper preserves the original AES_GCM_SIV(key, nonce) API used
# throughout the PDDB helper scripts (pddbcommon.py, backalyzer.py, etc.).

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.exceptions import InvalidTag


class AES_GCM_SIV(object):
    def __init__(self, key_gen_key, nonce):
        self._cipher = AESGCMSIV(key_gen_key)
        self._nonce = nonce

    def encrypt(self, plaintext, additional_data):
        """Encrypt plaintext with additional authenticated data.

        Returns ciphertext with 16-byte authentication tag appended.
        """
        return self._cipher.encrypt(
            self._nonce, plaintext, additional_data
        )

    def decrypt(self, ciphertext, additional_data):
        """Decrypt ciphertext (with appended tag) and verify AAD.

        Raises ValueError on authentication failure, preserving the
        exception type used by the previous implementation.
        """
        try:
            return self._cipher.decrypt(
                self._nonce, ciphertext, additional_data
            )
        except InvalidTag:
            raise ValueError('auth fail')

