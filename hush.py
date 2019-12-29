import base64
import os
import secrets
import string


from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import click

from dotenv import load_dotenv


class Context:
    def __init__(self):
        self.public_key_file = None
        self.private_key_file = None


dotenv_file = os.path.join(os.getcwd(), ".env")
if os.path.exists(dotenv_file):
    load_dotenv(dotenv_file)


context = click.make_pass_decorator(Context, ensure=True)


@click.group()
@click.version_option(".5")
@click.option(
    "-p",
    "--public-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PUBLIC_KEY_FILE",
    help="The file containing the public key, for encryption",
)
@click.option(
    "-r",
    "--private-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PRIVATE_KEY_FILE",
    help="The file containing the private key, for decryption",
)
@context
def cli(context, public_key_file, private_key_file):
    """ cli to interact with hush"""
    context.public_key_file = public_key_file
    context.private_key_file = private_key_file


@cli.command(help="Encrypt a secret")
@context
@click.argument("file", type=click.File("rb"), required=True, default="-")
def encrypt(context, file):
    data = file.read()

    public_key = RSA.import_key(context.public_key_file.read())
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
@context
@click.argument("file", type=click.File("rb"), required=True, default="-")
def decrypt(context, file):
    ciphertext_base64 = file.read()
    buffer = base64.b64decode(ciphertext_base64)
    private_key = RSA.import_key(context.private_key_file.read())
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
    alphabet = ""
    if "a" in character_classes:
        alphabet += string.ascii_lowercase
    if "A" in character_classes:
        alphabet += string.ascii_uppercase
    if "8" in character_classes:
        alphabet += string.digits
    if "#" in character_classes:
        alphabet += r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
    pwd = "".join(secrets.choice(alphabet) for x in range(length))
    click.echo(pwd)
