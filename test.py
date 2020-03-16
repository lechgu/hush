import base64

from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP as _PKCS1_OAEP
from Crypto.Cipher import AES as _AES


secret_file = "/Users/Lech/.keys/ssn/lech"
private_key_file = "/Users/Lech/.ssh/lechgu_gmail_com_rsa"


def dump(arr):
    return "".join([f"{x:02x}" for x in arr])


def decrypt(data, key):

    private_key = _RSA.import_key(key)
    priv_key_len = private_key.size_in_bytes()

    enc_session_key = data[:priv_key_len]
    nonce = data[priv_key_len : priv_key_len + 16]

    tag = data[priv_key_len + 16 : priv_key_len + 32]
    ciphertext = data[priv_key_len + 32 :]

    cipher_rsa = _PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    print(f"session key: {dump(session_key)}")
    print(f"ciphertext: {dump(ciphertext)}")
    print(f"nonce: {dump(nonce)}")
    print(f"tag: {dump(tag)}")
    cipher_aes = _AES.new(session_key, _AES.MODE_EAX, nonce)
    plain_text = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(plain_text)


def main():
    with open(secret_file, "rb") as f:
        bytes = f.read()
        print(len(bytes))
        data = base64.b64decode(bytes)
        print(len(data))
        print(dump(data[:5]))
        print(dump(data[-5:]))

    with open(private_key_file) as f:
        key = f.read()
        print(len(key))
    decrypt(data, key)


if __name__ == "__main__":
    main()
