from pathlib import Path
from pipeshield.analyzers.secret_analyzer import SecretAnalyzer
from pipeshield.models import Severity


def test_detect_aws_access_key():
    analyzer = SecretAnalyzer()
    sample = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"
    findings = analyzer.analyze_file(Path("config.py"), sample)
    assert len(findings) == 1
    assert findings[0].rule_id == "PS-SEC-001"
    assert findings[0].severity == Severity.CRITICAL


def test_detect_github_token():
    analyzer = SecretAnalyzer()
    sample = "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    findings = analyzer.analyze_file(Path("deploy.sh"), sample)
    assert len(findings) == 1
    assert findings[0].rule_id == "PS-SEC-003"
    assert findings[0].severity == Severity.CRITICAL


def test_detect_openai_api_key():
    analyzer = SecretAnalyzer()
    sample = "openai.api_key = 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890'"
    findings = analyzer.analyze_file(Path("ai_service.py"), sample)
    assert len(findings) == 1
    assert findings[0].rule_id == "PS-SEC-005"


def test_detect_database_uri():
    analyzer = SecretAnalyzer()
    sample = "DATABASE_URL = 'postgres://admin:SuperSecretPass123!@db.internal:5432/production'"
    findings = analyzer.analyze_file(Path("settings.py"), sample)
    assert len(findings) == 1
    assert findings[0].rule_id == "PS-SEC-008"
    assert findings[0].severity == Severity.HIGH


def test_detect_private_key():
    analyzer = SecretAnalyzer()
    sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    findings = analyzer.analyze_file(Path("id_rsa"), sample)
    assert any(f.rule_id == "PS-SEC-007" for f in findings)


def test_ignore_clean_code():
    analyzer = SecretAnalyzer()
    sample = (
        "def calculate_total(items):\n"
        "    tax = 0.2\n"
        "    return sum(i.price for i in items) * (1 + tax)\n"
    )
    findings = analyzer.analyze_file(Path("logic.py"), sample)
    assert len(findings) == 0
