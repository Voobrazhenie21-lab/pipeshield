from __future__ import annotations

from pathlib import Path
from pipeshield.analyzers.base import BaseAnalyzer
from pipeshield.models import Finding
from pipeshield.rules.js_rules import JS_RULES


class JsReconAnalyzer(BaseAnalyzer):
    """Static analyzer for JavaScript/TypeScript bundles: hidden endpoints, DOM XSS sinks, source maps, and internal IP leaks."""

    SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    @property
    def name(self) -> str:
        return "JsReconAnalyzer"

    def can_handle(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for rule in JS_RULES:
                # Allow sourceMappingURL comments for PS-JS-003, skip standard comments for other rules
                if rule.id != "PS-JS-003" and (
                    stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
                ):
                    continue

                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            description=rule.description,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=str(file_path),
                            line_number=idx,
                            snippet=stripped[:180],
                            remediation=rule.remediation,
                            cwe_id=rule.cwe_id,
                        )
                    )

        return findings
