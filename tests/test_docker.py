from pathlib import Path
from pipeshield.analyzers.docker_analyzer import DockerAnalyzer
from pipeshield.models import Severity


def test_docker_missing_user():
    analyzer = DockerAnalyzer()
    dockerfile = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "CMD ['python', 'main.py']\n"
    )
    findings = analyzer.analyze_file(Path("Dockerfile"), dockerfile)
    assert any(f.rule_id == "PS-DOCK-001" for f in findings)


def test_docker_unpinned_latest():
    analyzer = DockerAnalyzer()
    dockerfile = (
        "FROM alpine:latest\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1\n"
    )
    findings = analyzer.analyze_file(Path("Dockerfile"), dockerfile)
    assert any(f.rule_id == "PS-DOCK-002" for f in findings)


def test_docker_credentials_in_env():
    analyzer = DockerAnalyzer()
    dockerfile = (
        "FROM python:3.12-slim\n"
        "ENV API_SECRET_KEY=abcdef1234567890\n"
        "USER appuser\n"
        "HEALTHCHECK CMD exit 0\n"
    )
    findings = analyzer.analyze_file(Path("Dockerfile"), dockerfile)
    assert any(f.rule_id == "PS-DOCK-003" for f in findings)


def test_docker_curl_pipe_sh():
    analyzer = DockerAnalyzer()
    dockerfile = (
        "FROM ubuntu:22.04\n"
        "RUN curl -fsSL https://get.docker.com | sh\n"
        "USER appuser\n"
        "HEALTHCHECK CMD exit 0\n"
    )
    findings = analyzer.analyze_file(Path("Dockerfile"), dockerfile)
    assert any(f.rule_id == "PS-DOCK-004" for f in findings)


def test_docker_compliant():
    analyzer = DockerAnalyzer()
    dockerfile = (
        "FROM python:3.12.3-slim-bookworm\n"
        "RUN groupadd -r appuser && useradd -r -g appuser appuser\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "USER appuser\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/ || exit 1\n"
        "CMD ['python', 'app.py']\n"
    )
    findings = analyzer.analyze_file(Path("Dockerfile"), dockerfile)
    critical_or_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_or_high) == 0
