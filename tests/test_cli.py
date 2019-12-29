from click.testing import CliRunner

from hush import cli


def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, "--version")
    assert "5.1" in result.output

