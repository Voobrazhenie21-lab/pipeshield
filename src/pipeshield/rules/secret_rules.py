from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern
from pipeshield.models import Severity, Category


@dataclass
class SecretRule:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: Pattern[str]
    remediation: str
    cwe_id: str = "CWE-798"
    requires_entropy: bool = False
    entropy_threshold: float = 3.6
    category: Category = Category.SECRETS


SECRET_RULES: list[SecretRule] = [
    SecretRule(
        id="PS-SEC-001",
        title="AWS Access Key ID exposed",
        description="Identified a standard AWS Access Key ID starting with 'AKIA' or 'ABIA'.",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        remediation="Revoke the exposed key in the AWS IAM Console immediately and use IAM Roles or environment variables in secrets manager.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-002",
        title="AWS Secret Access Key exposed",
        description="Identified an AWS Secret Access Key assigned to an AWS credential variable.",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        remediation="Rotate this AWS secret key immediately and verify CloudTrail logs for unauthorized API calls.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-003",
        title="GitHub Token exposed",
        description="Identified a GitHub Personal Access Token (classic 'ghp_' or fine-grained 'github_pat_').",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{60,100})\b"),
        remediation="Revoke the token in GitHub Settings > Developer settings > Personal access tokens. Use GitHub Secrets instead.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-004",
        title="Slack Webhook or Bot Token exposed",
        description="Identified a Slack Incoming Webhook URL or Bot OAuth Token (xoxb/xoxp).",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(https://hooks\.slack\.com/services/T[0-9A-Z_]{8}/B[0-9A-Z_]{8}/[0-9A-Za-z]{24}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})"
        ),
        remediation="Revoke the Slack token or webhook URL from the Slack API App dashboard.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-005",
        title="OpenAI API Key exposed",
        description="Identified an OpenAI API key (sk- or project sk-proj- format).",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(sk-[a-zA-Z0-9]{20,50}|sk-proj-[a-zA-Z0-9_-]{40,120})\b"),
        remediation="Revoke the key from the OpenAI Platform dashboard and verify organization billing usage.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-006",
        title="Stripe Live API Key exposed",
        description="Identified a Stripe Live Secret/Restricted Key ('sk_live_' or 'rk_live_').",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b"),
        remediation="Roll this key in the Stripe Dashboard > Developers > API keys immediately to avoid fraudulent transactions.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-007",
        title="Private Cryptographic Key block exposed",
        description="Identified an unencrypted private key header (RSA, DSA, EC, OPENSSH, or PGP).",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
        remediation="Remove the private key from the repository. Regenerate the keypair and deploy the public key only.",
        cwe_id="CWE-312",
    ),
    SecretRule(
        id="PS-SEC-008",
        title="Database connection string with embedded password",
        description="Identified a database URI containing hardcoded credentials (PostgreSQL, MySQL, MongoDB, Redis).",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_.-]+:([a-zA-Z0-9_.!@#$%^&*()+-]+)@[a-zA-Z0-9_.-]+"
        ),
        remediation="Inject database credentials via environment variables or secret stores (e.g., Vault, AWS Secrets Manager).",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-009",
        title="JSON Web Token (JWT) exposed",
        description="Identified a hardcoded JWT token structure with signature.",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        remediation="Ensure JWTs are dynamically minted and not committed to source control as static fixtures.",
        cwe_id="CWE-798",
    ),
    SecretRule(
        id="PS-SEC-010",
        title="Generic high-entropy secret assignment",
        description="Identified a high-entropy string assigned to a variable name indicating a password, secret, or token.",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]([^'\"]{14,})['\"]"
        ),
        remediation="Externalize confidential credentials to a secure secrets manager or runtime environment variables.",
        cwe_id="CWE-798",
        requires_entropy=True,
        entropy_threshold=3.6,
    ),
]
