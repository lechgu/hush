import base64
import contextlib
import getpass
import os

import click
from dotenv import load_dotenv

from . import keypairs, passwords, secrets

dotenv_file = os.path.join(os.getcwd(), ".env")
if os.path.exists(dotenv_file):
    load_dotenv(dotenv_file)


@contextlib.contextmanager
def configuration(config):
    c = {}
    config = os.path.expanduser(config)
    if os.path.exists(config):
        with open(config) as f:
            for line in f.readlines():
                vals = line.split("=")
                if vals and len(vals) == 2:
                    c[vals[0]] = c[vals[1]]
    yield c
    with open(config, "w") as f:
        for k, v in c.items():
            f.write(f"{k}={v}")


def config_callback(ctx, param, value):
    with configuration(ctx.obj["config"]) as c:
        pass
    return value


@click.group()
@click.version_option("2020.1.11")
@click.option(
    "--config",
    type=str,
    default="~/.hush",
    help="Config file name, default '~/.hush' ",
)
@click.pass_context
def cli(ctx, config):
    """ cli to interact with hush"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@cli.command(help="Encrypt a secret")
@click.option(
    "-p",
    "--public-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PUBLIC_KEY_FILE",
    help="The file containing the public key, for encryption",
    callback=config_callback,
)
@click.argument("file", type=click.File("rb"), required=True, default="-")
@click.pass_context
def encrypt(ctx, public_key_file, file):
    data = file.read()
    key = public_key_file.read()
    encrypted_data = secrets.encrypt(data, key)

    click.echo(base64.b64encode(encrypted_data))


@cli.command(help="Decrypt the secret")
@click.option(
    "-r",
    "--private-key-file",
    type=click.File(),
    required=True,
    envvar="HUSH_PRIVATE_KEY_FILE",
    help="The file containing the private key, for decryption",
    callback=config_callback,
)
@click.option(
    "-S",
    "--ask-passphrase",
    is_flag=True,
    default=False,
    help="prompt for the private key passphrase",
)
@click.option(
    "-s",
    "--passphrase",
    type=str,
    default=None,
    help="the private key passphrase",
)
@click.argument("file", type=click.File("rb"), required=True, default="-")
@click.pass_context
def decrypt(ctx, private_key_file, ask_passphrase, passphrase, file):
    if ask_passphrase and passphrase:
        raise click.UsageError(
            "only one of the 'passphrase' and 'ask-passphrase' can be set "
        )
    secret = passphrase
    if ask_passphrase:
        secret = getpass.getpass("Enter the passphrase: ")
    data = base64.b64decode(file.read())
    key = private_key_file.read()
    click.echo(secrets.decrypt(data, key, secret))


@cli.command(help="Generate random password")
@click.option(
    "-l",
    "--length",
    type=int,
    default=16,
    envvar="HUSH_PASSWORD_LENGTH",
    help="Password Length",
    callback=config_callback,
)
@click.option(
    "--character-classes",
    "-c",
    type=str,
    default="a",
    required=True,
    envvar="HUSH_CHARACTER_CLASSES",
    callback=config_callback,
    help="""Character classes, combination of the following: 
    'a' (lowercase), 
    'A' (upperase), 
    '8' (digit), 
    '#' (non-alphanumeric)
    """,  # noqa
)
@click.pass_context
def generate(ctx, length, character_classes):
    if length < len(character_classes):
        raise click.UsageError("password too short")

    pwd = passwords.generate(length, character_classes)
    click.echo(pwd)


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
    "-S",
    "--ask-passphrase",
    is_flag=True,
    default=False,
    help="prompt for the private key passphrase",
)
@click.option(
    "-s",
    "--passphrase",
    type=str,
    default=None,
    help="private key passphrase",
)
def keygen(name, bits, ask_passphrase, passphrase):
    if passphrase and ask_passphrase:
        raise click.UsageError(
            "only one of 'passphrase' or 'ask-passphrase' options can be set"
        )
    secret = passphrase
    if ask_passphrase:
        secret = getpass.getpass(
            "Enter desired passphrase, [ENTER] for none: "
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
    (private_key, public_key) = keypairs.generate(length, secret)

    with open(private_file_name, "wb") as f:
        f.write(private_key)
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
    default=False,
    help="Overwrite existing file",
    prompt="This will overwrite the private key file. continue?",
)
@click.option("-o", "--old-passphrase", default=None, help="old passphrase")
@click.option("-s", "--new-passphrase", default=None, help="new passphrase")
@click.option(
    "-S",
    "--ask-passphrase",
    is_flag=True,
    default=False,
    help="prompt for the passphrases",
)
def passphrase(
    private_key_file, yes, old_passphrase, new_passphrase, ask_passphrase
):
    if not yes:
        return
    if ask_passphrase:
        if old_passphrase or new_passphrase:
            raise click.UsageError(
                "cannot specify passphrases if 'ask-passphrase' is set"
            )
        old_passphrase = getpass.getpass("Old passphrase? [ENTER] if empty:")
        new_passphrase = getpass.getpass("New passphrase? [ENTER] if empty:")
        new_passphrase2 = getpass.getpass("Repeat new passphrase:")
        if new_passphrase != new_passphrase2:
            raise click.UsageError("Passphrases don't match")
        if not new_passphrase:
            new_passphrase = None
    with open(private_key_file, "rb") as f:
        new_key = keypairs.change_passphrase(
            f.read(), old_passphrase, new_passphrase
        )

    with open(private_key_file, "wb") as f:
        f.write(new_key)
