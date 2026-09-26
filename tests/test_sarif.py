from pipeshield.formatters.sarif import generate_sarif_dict
from pipeshield.models import Category, Finding, ScanResult, ScanSummary, Severity


def test_sarif_structure():
    finding = Finding(
        rule_id="PS-SEC-001",
        title="AWS Access Key ID exposed",
        description="Identified an AWS Access Key ID.",
        severity=Severity.CRITICAL,
        category=Category.SECRETS,
        file_path="src/config.py",
        line_number=12,
        snippet="AKIAIOSFODNN7EXAMPLE",
        remediation="Revoke the key in AWS IAM.",
        cwe_id="CWE-798",
    )
    result = ScanResult(
        findings=[finding],
        summary=ScanSummary(total_findings=1, critical_count=1),
        target_path=".",
    )

    sarif = generate_sarif_dict(result)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "PipeShield"
    assert len(run["results"]) == 1

    res = run["results"][0]
    assert res["ruleId"] == "PS-SEC-001"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
