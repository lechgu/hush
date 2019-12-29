import base64
import getpass
import os
import random
import secrets
import string


from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import click

from dotenv import load_dotenv

dotenv_file = os.path.join(os.getcwd(), ".env")
if os.path.exists(dotenv_file):
    load_dotenv(dotenv_file)


@click.group()
@click.version_option(".5.1")
def cli():
    """ cli to interact with hush"""
    pass


@cli.command(help="Encrypt a secret")
@click.option(
    "-p",
    "--public-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PUBLIC_KEY_FILE",
    help="The file containing the public key, for encryption",
)
@click.argument("file", type=click.File("rb"), required=True, default="-")
def encrypt(public_key_file, file):
    data = file.read()

    public_key = RSA.import_key(public_key_file.read())
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce

    cipher_rsa = PKCS1_OAEP.new(public_key)

    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    enc_session_key = cipher_rsa.encrypt(session_key)

    ciphertext_base64 = base64.b64encode(
        enc_session_key + nonce + tag + ciphertext
    )
    click.echo(ciphertext_base64)


@cli.command(help="Decrypt the secret")
@click.option(
    "-r",
    "--private-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PRIVATE_KEY_FILE",
    help="The file containing the private key, for decryption",
)
@click.option(
    "-P",
    "--passphrase",
    is_flag=True,
    default=False,
    help="prompt for the private key passphrase",
)
@click.argument("file", type=click.File("rb"), required=True, default="-")
def decrypt(private_key_file, passphrase, file):
    secret = None
    if passphrase:
        secret = getpass.getpass("Enter the passphrase: ")
    ciphertext_base64 = file.read()
    buffer = base64.b64decode(ciphertext_base64)
    private_key = RSA.import_key(private_key_file.read(), secret)
    enc_session_key = buffer[: private_key.size_in_bytes()]
    nonce = buffer[
        private_key.size_in_bytes() : private_key.size_in_bytes() + 16
    ]
    tag = buffer[
        private_key.size_in_bytes() + 16 : private_key.size_in_bytes() + 32
    ]
    ciphertext = buffer[private_key.size_in_bytes() + 32 :]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    click.echo(data)


@cli.command(help="Generate random password")
@click.option("-l", "--length", type=int, default=16, help="Password Length")
@click.option(
    "--character-classes",
    "-c",
    type=str,
    default="a",
    required=True,
    envvar="HUSH_CHARACTER_CLASSES",
    help="""Character classes, combination of the following: 
    'a' (lowercase), 
    'A' (upperase), 
    '8' (digit), 
    '#' (non-alphanumeric)
    """,  # noqa
)
def generate(length, character_classes):
    if length < len(character_classes):
        raise click.UsageError("password too short")
    alphabet = ""
    pwd = []
    if "a" in character_classes:
        alphabet += string.ascii_lowercase
        pwd += secrets.choice(string.ascii_lowercase)
    if "A" in character_classes:
        alphabet += string.ascii_uppercase
        pwd += secrets.choice(string.ascii_uppercase)
    if "8" in character_classes:
        alphabet += string.digits
        pwd += secrets.choice(string.digits)
    if "#" in character_classes:
        non_alphahumerical = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
        alphabet += non_alphahumerical
        pwd += secrets.choice(non_alphahumerical)
    random.shuffle(pwd)
    pwd += [secrets.choice(alphabet) for x in range(length - len(pwd))]
    click.echo("".join(pwd))


@cli.command(help="Generate RSA private/public key pair")
@click.option(
    "-n", "--name", type=str, default="rsa", help="base file name for keys"
)
@click.option(
    "-b",
    "--bits",
    type=click.Choice(["1024", "2048", "3072"]),
    default="2048",
    help="key length size, in bits, by default 2048",
)
@click.option(
    "-P",
    "--passphrase",
    is_flag=True,
    default=False,
    help="prompt for the private key passphrase",
)
def keygen(name, bits, passphrase):
    secret = None
    if passphrase:
        secret = getpass.getpass(
            "Enter desired passphrase, [ENTER for none]: "
        )
        if secret:
            secret2 = getpass.getpass("Repeat passphrase: ")
            if secret != secret2:
                raise click.UsageError("Passphrases don't match")
        else:
            secret = None
    length = int(bits)
    private_file_name = f"{name}.pri"
    public_file_name = f"{name}.pub"
    key = RSA.generate(length)
    private_key = key.export_key("PEM", secret)
    with open(private_file_name, "wb") as f:
        f.write(private_key)
    public_key = key.publickey().export_key()
    with open(public_file_name, "wb") as f:
        f.write(public_key)
    click.echo(
        f"Private key stored in {private_file_name}, "
        f"public key stored in {public_file_name}"
    )


def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


@cli.command(help="Add/remove/change passprase in the private key file")
@click.option(
    "-r",
    "--private-key-file",
    type=str,
    required=True,
    help="Existing private key file",
)
@click.option(
    "--yes",
    is_flag=True,
    callback=abort_if_false,
    expose_value=False,
    prompt="Are you sure you want to overwrite the passphrase?",
)
def passphrase(private_key_file):
    if not os.path.exists(private_key_file):
        raise click.UsageError("File does not exist")
    secret = getpass.getpass("Existing passphrase, [ENTER] if None ")
    if not secret:
        secret = None
    with open(private_key_file, "rb") as f:
        key = RSA.importKey(f.read(), secret)
    new_secret = getpass.getpass("New passphrase, [ENTER] if none")
    new_secret2 = getpass.getpass("Repeat new passphrase")
    if new_secret != new_secret2:
        raise click.UsageError("Passphrases don't match")
    if not new_secret:
        new_secret = None
    private_key = key.export_key(
        format="PEM",
        passphrase=new_secret,
        pkcs=8,
        protection="scryptAndAES128-CBC",
    )
    with open(private_key_file, "wb") as f:
        f.write(private_key)
