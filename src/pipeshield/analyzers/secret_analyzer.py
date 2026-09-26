from __future__ import annotations

import os
from pathlib import Path
from pipeshield.analyzers.base import BaseAnalyzer
from pipeshield.core.entropy import is_high_entropy, mask_secret
from pipeshield.models import Finding
from pipeshield.rules.secret_rules import SECRET_RULES, SecretRule


IGNORE_EXTENSIONS = {
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".pyc",
    ".pyd",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".pdf",
}

IGNORE_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "composer.lock",
    "Pipfile.lock",
}


class SecretAnalyzer(BaseAnalyzer):
    """Detects credentials, API keys, private keys, and high-entropy secrets in code and configuration."""

    def __init__(self, rules: list[SecretRule] | None = None) -> None:
        self.rules = rules if rules is not None else SECRET_RULES

    @property
    def name(self) -> str:
        return "SecretAnalyzer"

    def can_handle(self, file_path: Path) -> bool:
        if file_path.name in IGNORE_FILENAMES:
            return False
        if file_path.suffix.lower() in IGNORE_EXTENSIONS:
            return False
        return True

    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip empty lines or standard comments that only contain documentation
            if not stripped or len(stripped) < 10:
                continue

            matched_specific = False
            for rule in self.rules:
                if matched_specific and rule.requires_entropy:
                    continue

                match = rule.pattern.search(line)
                if not match:
                    continue

                # If the rule has capture groups, test the captured secret; otherwise use the entire match
                candidate = match.group(1) if match.groups() else match.group(0)

                # Entropy check if required by the rule
                if rule.requires_entropy:
                    if not is_high_entropy(candidate, threshold=rule.entropy_threshold):
                        continue
                else:
                    matched_specific = True

                # Redact candidate token in snippet
                redacted_snippet = line.replace(candidate, mask_secret(candidate))

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        category=rule.category,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=redacted_snippet.strip(),
                        remediation=rule.remediation,
                        cwe_id=rule.cwe_id,
                    )
                )

        return findings
