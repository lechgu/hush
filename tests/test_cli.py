import os
import string
from contextlib import contextmanager

from click.testing import CliRunner

from hush import cli


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


def test_version():
    runner = CliRunner()
    output = runner.invoke(cli, "--version").output.strip()
<<<<<<< HEAD
    assert "5.2" in output
=======
<<<<<<< HEAD
    assert "5.1" in output
=======
    assert "5.2" in output
>>>>>>> devel
>>>>>>> master


def test_generate_default():
    runner = CliRunner()
    output = runner.invoke(cli, "generate").output.strip()
    assert len(output) == 16


def test_generate_lowercase():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "a"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == 16
    assert all([x in string.ascii_lowercase for x in output])


def test_generate_uppercase():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "A"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == 16
    assert all([x in string.ascii_uppercase for x in output])


def test_generate_digits():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "8"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert len(output) == 16
    assert all([x in string.digits for x in output])


def test_generate_nonalphanumeric():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "-c", "#"])
    assert result.exit_code == 0
    output = result.output.strip()
    nonalphanumeric = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
    assert len(output) == 16
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
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "rsa.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_keygen_name():
    with keypair(name="foo"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "foo.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "foo.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_keygen_passphrase():
    with keypair(passphrase="bar"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-s", "bar"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_add_passphrase():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "rsa.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli, ["passphrase", "-r", "rsa.pri", "-s", "boo", "--yes"]
        )
        assert result.exit_code == 0
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-s", "boo"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_strip_passphrase():
    with keypair(passphrase="bar"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-s", "bar"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli, ["passphrase", "-r", "rsa.pri", "--yes", "-o", "bar"]
        )
        assert result.exit_code == 0
        result = runner.invoke(cli, ["decrypt", "-r", "rsa.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_change_passphrase():
    with keypair(passphrase="foo"):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-s", "foo"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(
            cli,
            ["passphrase", "-r", "rsa.pri", "--yes", "-o", "foo", "-s", "bar"],
        )
        assert result.exit_code == 0
        result = runner.invoke(
            cli, ["decrypt", "-r", "rsa.pri", "-s", "bar"], input=output
        )
        assert result.exit_code == 0
        assert result.output.strip() == "secret"


def test_change_passphrase_empty():
    with keypair():
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "rsa.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "rsa.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
        result = runner.invoke(cli, ["passphrase", "-r", "rsa.pri", "--yes"],)
        assert result.exit_code == 0
        result = runner.invoke(cli, ["decrypt", "-r", "rsa.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"
