import os
import string
from contextlib import contextmanager

from click.testing import CliRunner

from hush import cli


@contextmanager
def keypair(name="rsa"):
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "-n", name])
    yield
    os.remove(f"{name}.pub")
    os.remove(f"{name}.pri")


def test_version():
    runner = CliRunner()
    output = runner.invoke(cli, "--version").output.strip()
    assert "5.1" in output


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
    with keypair(name='foo'):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["encrypt", "-p", "foo.pub"], input="secret"
        )
        assert result.exit_code == 0
        output = result.output
        result = runner.invoke(cli, ["decrypt", "-r", "foo.pri"], input=output)
        assert result.exit_code == 0
        assert result.output.strip() == "secret"

