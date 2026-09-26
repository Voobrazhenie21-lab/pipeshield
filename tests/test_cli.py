from click.testing import CliRunner
from pipeshield.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "pipeshield" in result.output


def test_cli_rules():
    runner = CliRunner()
    result = runner.invoke(cli, ["rules"])
    assert result.exit_code == 0
    assert "PS-SEC-001" in result.output
    assert "PS-DOCK-001" in result.output
    assert "PS-CICD-001" in result.output


def test_cli_scan_clean(tmp_path):
    # Create clean directory
    clean_file = tmp_path / "hello.py"
    clean_file.write_text("print('Hello world!')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_cli_scan_vulnerable(tmp_path):
    # Create file with AWS key
    vuln_file = tmp_path / "credentials.py"
    vuln_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "PS-SEC-001" in result.output
