import string

from click.testing import CliRunner

from hush import cli


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
    output = runner.invoke(cli, "generate -c a").output.strip()
    assert len(output) == 16
    assert all([x in string.ascii_lowercase for x in output])


def test_generate_uppercase():
    runner = CliRunner()
    output = runner.invoke(cli, "generate -c A").output.strip()
    assert len(output) == 16
    assert all([x in string.ascii_uppercase for x in output])


def test_generate_digits():
    runner = CliRunner()
    output = runner.invoke(cli, "generate -c 8").output.strip()
    assert len(output) == 16
    assert all([x in string.digits for x in output])


def test_generate_nonalphanumeric():
    runner = CliRunner()
    nonalphanumeric = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
    output = runner.invoke(cli, "generate -c #").output.strip()
    assert len(output) == 16
    assert all([x in nonalphanumeric for x in output])


def test_generate_mixed_classes():
    runner = CliRunner()
    nonalphanumeric = r"~!@#$%^&*_-+=|\(){}[]:;<>,.?/"
    output = runner.invoke(cli, "generate -c aA8#").output.strip()
    assert any([x in string.ascii_lowercase for x in output])
    assert any([x in string.ascii_uppercase for x in output])
    assert any([x in string.digits for x in output])
    assert any([x in nonalphanumeric for x in output])


def test_generate_len():
    runner = CliRunner()
    output = runner.invoke(cli, "generate -l 42").output.strip()
    assert len(output) == 42

