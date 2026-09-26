from __future__ import annotations

import re
from pathlib import Path
from pipeshield.analyzers.base import BaseAnalyzer
from pipeshield.models import Finding, Severity, Category
from pipeshield.rules.docker_rules import DOCKER_RULES, DockerRule


class DockerAnalyzer(BaseAnalyzer):
    """Analyzes Dockerfiles and Containerfiles against container hardening best practices."""

    def __init__(self, rules: list[DockerRule] | None = None) -> None:
        self.rules = rules if rules is not None else DOCKER_RULES

    @property
    def name(self) -> str:
        return "DockerAnalyzer"

    def can_handle(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return (
            name == "dockerfile"
            or name.startswith("dockerfile.")
            or name.endswith(".dockerfile")
            or name == "containerfile"
            or name.endswith(".containerfile")
        )

    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        has_user_instruction = False
        user_is_root = False
        has_healthcheck = False
        last_from_line_no = 1
        is_from_scratch = False

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check FROM instructions (unpinned images)
            from_match = re.match(r"^\s*FROM\s+([^\s]+)(?:\s+AS\s+\w+)?", line, re.IGNORECASE)
            if from_match:
                last_from_line_no = line_no
                # Reset per-stage checks
                has_user_instruction = False
                user_is_root = False

                image_ref = from_match.group(1).strip()
                if image_ref.lower() == "scratch":
                    is_from_scratch = True
                    continue

                is_from_scratch = False
                # Check for unpinned image tag
                if ":" not in image_ref and "@" not in image_ref:
                    rule = self._get_rule("PS-DOCK-002")
                    if rule:
                        findings.append(
                            self._create_finding(
                                rule,
                                file_path,
                                line_no,
                                stripped,
                                f"Base image '{image_ref}' has no version tag specified.",
                            )
                        )
                elif image_ref.endswith(":latest"):
                    rule = self._get_rule("PS-DOCK-002")
                    if rule:
                        findings.append(
                            self._create_finding(
                                rule,
                                file_path,
                                line_no,
                                stripped,
                                f"Base image '{image_ref}' uses mutable ':latest' tag.",
                            )
                        )

            # Check USER instruction
            user_match = re.match(r"^\s*USER\s+([^\s]+)", line, re.IGNORECASE)
            if user_match:
                has_user_instruction = True
                user_val = user_match.group(1).strip().lower()
                user_is_root = user_val in ("root", "0", "0:0")

            # Check HEALTHCHECK
            if re.match(r"^\s*HEALTHCHECK\s+", line, re.IGNORECASE):
                has_healthcheck = True

            # Check ENV/ARG credentials (PS-DOCK-003)
            rule_003 = self._get_rule("PS-DOCK-003")
            if rule_003 and rule_003.pattern and rule_003.pattern.search(line):
                findings.append(self._create_finding(rule_003, file_path, line_no, stripped))

            # Check curl | sh (PS-DOCK-004)
            rule_004 = self._get_rule("PS-DOCK-004")
            if rule_004 and rule_004.pattern and rule_004.pattern.search(line):
                findings.append(self._create_finding(rule_004, file_path, line_no, stripped))

            # Check ADD instead of COPY (PS-DOCK-005)
            rule_005 = self._get_rule("PS-DOCK-005")
            if rule_005 and rule_005.pattern and rule_005.pattern.search(line):
                findings.append(self._create_finding(rule_005, file_path, line_no, stripped))

            # Check sudo installation (PS-DOCK-007)
            rule_007 = self._get_rule("PS-DOCK-007")
            if rule_007 and rule_007.pattern and rule_007.pattern.search(line):
                findings.append(self._create_finding(rule_007, file_path, line_no, stripped))

        # Check final USER status (PS-DOCK-001)
        if not is_from_scratch:
            rule_001 = self._get_rule("PS-DOCK-001")
            if rule_001:
                if not has_user_instruction:
                    findings.append(
                        self._create_finding(
                            rule_001,
                            file_path,
                            last_from_line_no,
                            "Missing USER directive",
                            "Container executes as default root user (UID 0).",
                        )
                    )
                elif user_is_root:
                    findings.append(
                        self._create_finding(
                            rule_001,
                            file_path,
                            last_from_line_no,
                            "Explicit USER root",
                            "Container explicitly switches to root user.",
                        )
                    )

            # Check missing HEALTHCHECK (PS-DOCK-006)
            rule_006 = self._get_rule("PS-DOCK-006")
            if rule_006 and not has_healthcheck:
                findings.append(
                    self._create_finding(
                        rule_006,
                        file_path,
                        1,
                        "Missing HEALTHCHECK",
                        "No HEALTHCHECK instruction defined in Dockerfile.",
                    )
                )

        return findings

    def _get_rule(self, rule_id: str) -> DockerRule | None:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def _create_finding(
        self,
        rule: DockerRule,
        file_path: Path,
        line_number: int,
        snippet: str,
        custom_desc: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            description=custom_desc or rule.description,
            severity=rule.severity,
            category=Category.DOCKER,
            file_path=str(file_path),
            line_number=line_number,
            snippet=snippet,
            remediation=rule.remediation,
            cwe_id=rule.cwe_id,
        )
