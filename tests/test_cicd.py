from pathlib import Path
from pipeshield.analyzers.cicd_analyzer import CicdAnalyzer
from pipeshield.models import Severity


def test_cicd_write_all():
    analyzer = CicdAnalyzer()
    workflow = (
        "name: Deploy\n"
        "on: push\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    timeout-minutes: 10\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo 'build'\n"
    )
    findings = analyzer.analyze_file(Path(".github/workflows/deploy.yml"), workflow)
    assert any(f.rule_id == "PS-CICD-001" for f in findings)


def test_cicd_unpinned_action():
    analyzer = CicdAnalyzer()
    workflow = (
        "name: Test\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    timeout-minutes: 10\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    findings = analyzer.analyze_file(Path(".github/workflows/test.yml"), workflow)
    assert any(f.rule_id == "PS-CICD-002" for f in findings)


def test_cicd_script_injection():
    analyzer = CicdAnalyzer()
    workflow = (
        "name: PR Greeting\n"
        "on: pull_request\n"
        "jobs:\n"
        "  greet:\n"
        "    timeout-minutes: 5\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo 'PR Title is: ${{ github.event.pull_request.title }}'\n"
    )
    findings = analyzer.analyze_file(Path(".github/workflows/greet.yml"), workflow)
    assert any(f.rule_id == "PS-CICD-003" for f in findings)


def test_cicd_missing_timeout():
    analyzer = CicdAnalyzer()
    workflow = (
        "name: Build\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo 'hi'\n"
    )
    findings = analyzer.analyze_file(Path(".github/workflows/build.yml"), workflow)
    assert any(f.rule_id == "PS-CICD-005" for f in findings)
