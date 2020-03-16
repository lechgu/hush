from Crypto.Cipher import AES as _AES
from Crypto.Cipher import PKCS1_OAEP as _PKCS1_OAEP
from Crypto.PublicKey import RSA as _RSA
from Crypto.Random import get_random_bytes as _get_random_bytes


def encrypt(data, key, mode):
    aes_mode = _AES.MODE_GCM if mode == "gcm" else _AES.MODE_EAX
    session_key = _get_random_bytes(16)
    cipher_aes = _AES.new(session_key, aes_mode)
    nonce = cipher_aes.nonce

    public_key = _RSA.import_key(key)
    cipher_rsa = _PKCS1_OAEP.new(public_key)

    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key + nonce + tag + ciphertext


def decrypt(data, key, mode, passphrase=None):
    aes_mode = _AES.MODE_GCM if mode == "gcm" else _AES.MODE_EAX
    private_key = _RSA.import_key(key, passphrase)
    enc_session_key = data[: private_key.size_in_bytes()]
    nonce = data[
        private_key.size_in_bytes() : private_key.size_in_bytes() + 16
    ]
    tag = data[
        private_key.size_in_bytes() + 16 : private_key.size_in_bytes() + 32
    ]
    ciphertext = data[private_key.size_in_bytes() + 32 :]

    cipher_rsa = _PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = _AES.new(session_key, aes_mode, nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)
