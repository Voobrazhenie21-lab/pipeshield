from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern
from pipeshield.models import Severity, Category


@dataclass
class CicdRule:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: Optional[Pattern[str]] = None
    remediation: str = ""
    cwe_id: str = "CWE-829"
    category: Category = Category.CICD


CICD_RULES: list[CicdRule] = [
    CicdRule(
        id="PS-CICD-001",
        title="Overly permissive workflow permissions (write-all)",
        description="The workflow or job explicitly grants `permissions: write-all`. This violates the principle of least privilege and allows compromised steps to write to all repo resources.",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"^\s*permissions:\s*write-all\s*$", re.IGNORECASE | re.MULTILINE),
        remediation="Grant only the minimal required permissions, e.g., `permissions: { contents: read, pull-requests: write }`.",
        cwe_id="CWE-250",
    ),
    CicdRule(
        id="PS-CICD-002",
        title="Unpinned GitHub Action (mutable tag/branch used instead of full commit SHA)",
        description="A third-party action is pinned to a mutable tag (e.g. `@v3`, `@main`) rather than a full 40-character commit SHA. Attackers who compromise the upstream repository can overwrite tags.",
        severity=Severity.HIGH,
        remediation="Pin third-party actions to a full 40-character commit SHA, e.g., `uses: actions/checkout@b4ffde5c8fafcde5c04619f5ecd0426728247c1b # v4.1.1`.",
        cwe_id="CWE-829",
    ),
    CicdRule(
        id="PS-CICD-003",
        title="Potential script injection via untrusted GitHub context in 'run'",
        description="Untrusted user input (e.g., pull request title, issue body, head_ref) is interpolated directly into an inline shell `run` script, allowing arbitrary command execution.",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)\s*\}\}",
            re.IGNORECASE,
        ),
        remediation="Pass untrusted inputs via intermediate environment variables rather than direct inline string interpolation: `env: PR_TITLE: ${{ github.event.pull_request.title }}`.",
        cwe_id="CWE-78",
    ),
    CicdRule(
        id="PS-CICD-004",
        title="Dangerous use of pull_request_target with pull_request ref checkout",
        description="The workflow triggers on `pull_request_target` (which grants repository secrets and write tokens) but checks out untrusted code from the fork.",
        severity=Severity.CRITICAL,
        remediation="Never check out untrusted fork code in a `pull_request_target` workflow. Use `pull_request` trigger for untrusted workflows.",
        cwe_id="CWE-829",
    ),
    CicdRule(
        id="PS-CICD-005",
        title="Missing job execution timeout",
        description="The CI job does not specify `timeout-minutes`. A hung build or malicious PR can consume all available runner minutes.",
        severity=Severity.LOW,
        remediation="Specify a reasonable timeout for each job, e.g., `timeout-minutes: 15`.",
        cwe_id="CWE-400",
    ),
]
