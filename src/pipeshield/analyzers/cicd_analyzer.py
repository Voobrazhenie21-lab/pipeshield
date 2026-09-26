from __future__ import annotations

import re
from pathlib import Path
from typing import Any
import yaml

from pipeshield.analyzers.base import BaseAnalyzer
from pipeshield.models import Finding, Severity, Category
from pipeshield.rules.cicd_rules import CICD_RULES, CicdRule


HEX_SHA_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")


class CicdAnalyzer(BaseAnalyzer):
    """Analyzes CI/CD pipeline definitions (GitHub Actions workflows) for supply chain security risks."""

    def __init__(self, rules: list[CicdRule] | None = None) -> None:
        self.rules = rules if rules is not None else CICD_RULES

    @property
    def name(self) -> str:
        return "CicdAnalyzer"

    def can_handle(self, file_path: Path) -> bool:
        posix_str = file_path.as_posix()
        is_github_workflow = (
            (".github/workflows" in posix_str or ".github\\workflows" in str(file_path))
            and file_path.suffix.lower() in (".yml", ".yaml")
        )
        is_gitlab_ci = ".gitlab-ci" in file_path.name.lower()
        return is_github_workflow or is_gitlab_ci

    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        # Parse YAML structure safely if possible
        parsed_yaml: dict[str, Any] | None = None
        try:
            parsed_yaml = yaml.safe_load(content)
            if not isinstance(parsed_yaml, dict):
                parsed_yaml = None
        except Exception:
            parsed_yaml = None

        # 1. Line-by-line checks
        inside_run_block = False
        run_indent = 0

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check PS-CICD-001: permissions: write-all
            if re.search(r"^\s*permissions:\s*write-all\s*$", line, re.IGNORECASE):
                rule = self._get_rule("PS-CICD-001")
                if rule:
                    findings.append(self._create_finding(rule, file_path, line_no, stripped))

            # Check PS-CICD-002: Unpinned GitHub Action (uses: owner/repo@tag)
            uses_match = re.search(r"^\s*-\s*uses:\s*([^\s#]+)", line, re.IGNORECASE) or re.search(
                r"^\s*uses:\s*([^\s#]+)", line, re.IGNORECASE
            )
            if uses_match:
                action_ref = uses_match.group(1).strip().strip("'\"")
                # Ignore local actions or docker actions
                if not action_ref.startswith("./") and not action_ref.startswith("docker://"):
                    if "@" in action_ref:
                        action_name, version = action_ref.split("@", 1)
                        if not HEX_SHA_REGEX.match(version):
                            rule = self._get_rule("PS-CICD-002")
                            if rule:
                                findings.append(
                                    self._create_finding(
                                        rule,
                                        file_path,
                                        line_no,
                                        stripped,
                                        f"Action '{action_name}' is pinned to mutable ref '@{version}' instead of an immutable 40-char commit SHA.",
                                    )
                                )
                    else:
                        rule = self._get_rule("PS-CICD-002")
                        if rule:
                            findings.append(
                                self._create_finding(
                                    rule,
                                    file_path,
                                    line_no,
                                    stripped,
                                    f"Action '{action_ref}' has no version or SHA pin specified.",
                                )
                            )

            # Check PS-CICD-003: Script injection via untrusted context in run:
            if re.match(r"^\s*run:\s*", line, re.IGNORECASE):
                inside_run_block = True
                run_indent = len(line) - len(line.lstrip())

            # Detect untrusted expressions
            untrusted_match = re.search(
                r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)\s*\}\}",
                line,
                re.IGNORECASE,
            )
            if untrusted_match and (inside_run_block or "run:" in line):
                rule = self._get_rule("PS-CICD-003")
                if rule:
                    findings.append(
                        self._create_finding(
                            rule,
                            file_path,
                            line_no,
                            stripped,
                            f"Untrusted context '{untrusted_match.group(0)}' used directly in shell execution script.",
                        )
                    )

        # 2. Structural checks on parsed YAML
        if parsed_yaml:
            findings.extend(self._check_structural(file_path, parsed_yaml, lines))

        return findings

    def _check_structural(
        self,
        file_path: Path,
        yaml_data: dict[str, Any],
        lines: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check PS-CICD-004: pull_request_target with untrusted head checkout
        triggers = yaml_data.get("on") or yaml_data.get(True)
        has_pr_target = False
        if isinstance(triggers, str) and triggers == "pull_request_target":
            has_pr_target = True
        elif isinstance(triggers, list) and "pull_request_target" in triggers:
            has_pr_target = True
        elif isinstance(triggers, dict) and "pull_request_target" in triggers:
            has_pr_target = True

        jobs = yaml_data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job_info in jobs.items():
                if not isinstance(job_info, dict):
                    continue

                # Check PS-CICD-005: Missing job timeout
                if "timeout-minutes" not in job_info:
                    line_no = self._find_job_line(lines, job_id)
                    rule = self._get_rule("PS-CICD-005")
                    if rule:
                        findings.append(
                            self._create_finding(
                                rule,
                                file_path,
                                line_no,
                                f"job '{job_id}': missing timeout-minutes",
                                f"Job '{job_id}' does not define 'timeout-minutes'. Runaway jobs could deplete CI minutes.",
                            )
                        )

                # Check if checking out PR head ref under pull_request_target
                if has_pr_target:
                    steps = job_info.get("steps", [])
                    if isinstance(steps, list):
                        for step in steps:
                            if isinstance(step, dict) and "uses" in step:
                                if "checkout" in str(step["uses"]).lower():
                                    step_with = step.get("with", {})
                                    ref = str(step_with.get("ref", ""))
                                    if "pull_request.head" in ref or "head_ref" in ref:
                                        line_no = self._find_job_line(lines, job_id)
                                        rule = self._get_rule("PS-CICD-004")
                                        if rule:
                                            findings.append(
                                                self._create_finding(
                                                    rule,
                                                    file_path,
                                                    line_no,
                                                    f"uses: {step['uses']}, ref: {ref}",
                                                    "Workflow uses 'pull_request_target' trigger and checks out untrusted PR head commit with elevated repository tokens.",
                                                )
                                            )

        return findings

    def _find_job_line(self, lines: list[str], job_id: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if re.match(rf"^\s*{re.escape(job_id)}\s*:\s*$", line):
                return idx
        return 1

    def _get_rule(self, rule_id: str) -> CicdRule | None:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def _create_finding(
        self,
        rule: CicdRule,
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
            category=Category.CICD,
            file_path=str(file_path),
            line_number=line_number,
            snippet=snippet,
            remediation=rule.remediation,
            cwe_id=rule.cwe_id,
        )
