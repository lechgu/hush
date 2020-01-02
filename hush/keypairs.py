from Crypto.PublicKey import RSA


def generate(bits, passphrase):
    key = RSA.generate(bits)
    private_key = key.export_key("PEM", passphrase)
    public_key = key.publickey().export_key()
    return (private_key, public_key)


def change_passphrase(key, old_passphrase, new_passphrase):
    key = RSA.importKey(key, old_passphrase)
    return key.export_key(
        passphrase=new_passphrase, pkcs=8, protection="scryptAndAES128-CBC"
    )
