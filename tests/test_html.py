from pipeshield.formatters.html_out import generate_html_report, export_html
from pipeshield.models import Finding, ScanResult, ScanSummary, Severity, Category


def test_generate_html_clean():
    result = ScanResult(
        findings=[],
        summary=ScanSummary(scanned_files=5, total_findings=0, failed=False),
        target_path="src/",
    )
    html_out = generate_html_report(result)
    assert "<!DOCTYPE html>" in html_out
    assert "Scan Clean" in html_out
    assert "Repository is Clean!" in html_out


def test_generate_html_with_findings(tmp_path):
    finding = Finding(
        rule_id="PS-SEC-001",
        title="AWS Access Key ID exposed",
        description="Identified an AWS Access Key ID.",
        severity=Severity.CRITICAL,
        category=Category.SECRETS,
        file_path="src/config.py",
        line_number=15,
        snippet="AKIAIOSFODNN7EXAMPLE",
        remediation="Revoke key in AWS IAM.",
        cwe_id="CWE-798",
    )
    result = ScanResult(
        findings=[finding],
        summary=ScanSummary(scanned_files=10, total_findings=1, critical_count=1, failed=True),
        target_path=".",
    )
    html_out = generate_html_report(result)
    assert "Policy Failed" in html_out
    assert "PS-SEC-001" in html_out
    assert "AWS Access Key ID exposed" in html_out
    assert "CWE-798" in html_out
    assert "AKIAIOSFODNN7EXAMPLE" in html_out

    # Test file export
    report_file = tmp_path / "dashboard.html"
    export_html(result, report_file)
    assert report_file.exists()
    assert len(report_file.read_text(encoding="utf-8")) > 500
