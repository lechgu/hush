import os
import string
import tempfile

from click.testing import CliRunner

from hush import cli

import pytest


@pytest.fixture()
def keypair():
    runner = CliRunner()
    runner.invoke(cli, "keygen")
    yield "rsa.pub"
    os.remove("rsa.pub")
    os.remove("rsa.pri")


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
    result = runner.invoke(cli, "generate -l 42")
    assert result.exit_code == 0
    assert len(result.output.strip()) == 42


def test_encrypt(keypair):
    runner = CliRunner()
    output = runner.invoke(cli, "encrypt -p rsa.pub README.md").output.strip()
    assert len(output) > 0


def test_decrypt(keypair):
    runner = CliRunner()
    output = runner.invoke(cli, "encrypt -p rsa.pub README.md").output.strip()
    with tempfile.NamedTemporaryFile() as f:
        f.write(output.encode())
