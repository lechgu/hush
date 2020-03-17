import os
import string
from contextlib import contextmanager
from tempfile import mktemp

from click.testing import CliRunner

from hush import cli
from hush.console import DEFAULT_PASSWORD_LENGTH


@contextmanager
def keypair(name="rsa", passphrase=None):
    runner = CliRunner()
    args = (
        ["keygen", "-n", name, "-s", passphrase]
        if passphrase
        else ["keygen", "-n", name]
    )
    runner.invoke(cli, args)
    yield
    os.remove(f"{name}.pub")
    os.remove(f"{name}.pri")


@contextmanager
def config_file(lines):
    file_name = mktemp()
    with open(file_name, "w") as f:
        f.writelines(lines)
    yield file_name
    os.remove(file_name)


@contextmanager
def temp_file():
    file_name = mktemp()
    yield file_name
    os.remove(file_name)


def test_version():
    runner = CliRunner()
    output = runner.invoke(cli, "--version").output.strip()

    assert "202003.5" in output


def test_generate_default():
    runner = CliRunner()
    output = runner.invoke(cli, "generate").output.strip()
    assert len(output) == DEFAULT_PASSWORD_LENGTH


def test_generate_lowercase():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "a"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == DEFAULT_PASSWORD_LENGTH
    assert all([x in string.ascii_lowercase for x in output])


def test_generate_uppercase():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "A"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == DEFAULT_PASSWORD_LENGTH
    assert all([x in string.ascii_uppercase for x in output])


def test_generate_digits():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "8"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == DEFAULT_PASSWORD_LENGTH
    assert all([x in string.digits for x in output])


def test_generate_nonalphanumeric():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "#"])
    assert result.exit_code == 0
    output = result.output.strip()
    nonalphanumeric = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"

    assert len(output) == DEFAULT_PASSWORD_LENGTH

    assert all([x in nonalphanumeric for x in output])


def test_generate_mixed_classes():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "aA8#"])
    assert result.exit_code == 0
    output = result.output.strip()
    nonalphanumeric = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
    assert any([x in string.ascii_lowercase for x in output])
    assert any([x in string.ascii_uppercase for x in output])
    assert any([x in string.digits for x in output])
    assert any([x in nonalphanumeric for x in output])


def test_generate_len():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-l", "42"])
    assert result.exit_code == 0
    assert len(result.output.strip()) == 42


def test_encrypt_decrypt():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_encrypt_decrypt_eax():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "eax"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "eax"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_keygen_name():
    with keypair(name="foo"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "foo.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "foo.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_keygen_passphrase():
    with keypair(passphrase="bar"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli,
            ["decrypt", "-r", "rsa.pri", "-s", "bar", "-m", "gcm"],
            input=output,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_add_passphrase():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli, ["passphrase", "-r", "rsa.pri", "-s", "eax", "--yes"],
        )
        assert result.exit_code == 0
        result = runner.invoke(
            cli,
            ["decrypt", "-r", "rsa.pri", "-s", "eax", "-m", "gcm"],
            input=output,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_strip_passphrase():
    with keypair(passphrase="bar"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli,
            ["decrypt", "-r", "rsa.pri", "-s", "bar", "-m", "gcm"],
            input=output,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli, ["passphrase", "-r", "rsa.pri", "--yes", "-o", "bar"]
        )
        assert result.exit_code == 0
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_change_passphrase():
    with keypair(passphrase="foo"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli,
            ["decrypt", "-r", "rsa.pri", "-s", "foo", "-m", "gcm"],
            input=output,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli,
            ["passphrase", "-r", "rsa.pri", "--yes", "-o", "foo", "-s", "bar"],
        )
        assert result.exit_code == 0
        result = runner.invoke(
            cli,
            [
                "decrypt",
                "-r",
                "rsa.pri",
                "-s",
                "bar",
                "-m",
                "gcm",
                "-m",
                "gcm",
            ],
            input=output,
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_change_passphrase_empty():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub", "-m", "gcm"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(cli, ["passphrase", "-r", "rsa.pri", "--yes"],)
        assert result.exit_code == 0
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-m", "gcm"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_config_init():
    runner = CliRunner()
    with temp_file() as t:
        with keypair():
            result = runner.invoke(
                cli, ["-c", t, "init", "-r", "rsa.pri", "-p", "rsa.pub"],
            )
            assert result.exit_code == 0
            result = runner.invoke(cli, ["-c", t, "config", "encrypt.mode"])
            assert result.exit_code == 0
            assert result.output.strip() == "eax"


def test_config_init_override():
    runner = CliRunner()
    with temp_file() as t:
        with keypair():
            result = runner.invoke(
                cli, ["-c", t, "init", "-r", "rsa.pri", "-p", "rsa.pub"],
            )
            assert result.exit_code == 0
            result = runner.invoke(
                cli, ["-c", t, "config", "-s", "encrypt.mode", "gcm"]
            )
            assert result.exit_code == 0
            result = runner.invoke(cli, ["-c", t, "config", "encrypt.mode"])
            assert result.exit_code == 0
            assert result.output.strip() == "gcm"
            result = runner.invoke(
                cli,
                ["-c", t, "init", "-f", "-r", "rsa.pri", "-p", "rsa.pub",],
            )
            assert result.exit_code == 0


def test_alterantive_config():
    lines = """
    [generate]
    length = 40
    character_classes = a
    [decrypt]
    private_key_file = foo.pri
    mode  = eax

    [encrypt]
    public_key_file = foo.pub
    mode = eax
    """
    with keypair("foo"):
        with config_file(lines) as alternative_config:
            runner = CliRunner()
            result = runner.invoke(cli, ["-c", alternative_config, "generate"])
            assert result.exit_code == 0
            output = result.output.strip()
            assert len(output) == 40
            assert all([x in string.ascii_lowercase for x in output])
            result = runner.invoke(
                cli, ["encrypt", "-p", "foo.pub"], input="secret"
            )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "foo.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
