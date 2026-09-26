from __future__ import annotations

import time
from pathlib import Path
from typing import Sequence

from pipeshield.analyzers.base import BaseAnalyzer
from pipeshield.analyzers.cicd_analyzer import CicdAnalyzer
from pipeshield.analyzers.docker_analyzer import DockerAnalyzer
from pipeshield.analyzers.secret_analyzer import SecretAnalyzer
from pipeshield.config import Config
from pipeshield.models import Finding, ScanResult, ScanSummary, Severity


class Scanner:
    """Core security scanning engine for PipeShield."""

    def __init__(
        self,
        config: Config | None = None,
        analyzers: Sequence[BaseAnalyzer] | None = None,
    ) -> None:
        self.config = config or Config()
        self.analyzers: list[BaseAnalyzer] = list(
            analyzers
            if analyzers is not None
            else [SecretAnalyzer(), DockerAnalyzer(), CicdAnalyzer()]
        )

    def scan_path(self, target_path: str | Path) -> ScanResult:
        """Scan a file or directory for security vulnerabilities."""
        start_time = time.perf_counter()
        target = Path(target_path).resolve()

        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        root_dir = target if target.is_dir() else target.parent
        files_to_scan: list[Path] = []

        if target.is_file():
            if not self.config.should_ignore_file(target, root_dir):
                files_to_scan.append(target)
        else:
            for item in target.rglob("*"):
                if item.is_file() and not self.config.should_ignore_file(item, root_dir):
                    files_to_scan.append(item)

        raw_findings: list[Finding] = []
        scanned_count = 0

        for file_path in files_to_scan:
            try:
                # Read with fallback encoding and check for binary content
                with open(file_path, "rb") as bf:
                    raw_bytes = bf.read(4096)
                    # Skip binary files
                    if b"\0" in raw_bytes:
                        continue

                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                scanned_count += 1

                for analyzer in self.analyzers:
                    if analyzer.can_handle(file_path):
                        findings = analyzer.analyze_file(file_path, content)
                        raw_findings.extend(findings)

            except Exception:
                # Silently skip files that cannot be read (e.g. system permissions)
                continue

        # Filter out ignored findings according to configuration/suppression rules
        filtered_findings = [
            finding
            for finding in raw_findings
            if not self.config.is_finding_ignored(finding, root_dir)
        ]

        # Calculate metrics
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        crit_count = sum(1 for f in filtered_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in filtered_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in filtered_findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in filtered_findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in filtered_findings if f.severity == Severity.INFO)

        has_failed = any(f.severity >= self.config.fail_on for f in filtered_findings)

        summary = ScanSummary(
            scanned_files=scanned_count,
            total_findings=len(filtered_findings),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            scan_duration_ms=round(duration_ms, 2),
            failed=has_failed,
        )

        return ScanResult(
            findings=filtered_findings,
            summary=summary,
            target_path=str(target),
        )
