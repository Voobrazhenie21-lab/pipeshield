from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from pipeshield.models import ScanResult


def generate_sarif_dict(result: ScanResult) -> dict[str, Any]:
    """Generate a valid OASIS SARIF v2.1.0 data structure for GitHub Code Scanning."""
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    target_root = Path(result.target_path)
    if target_root.is_file():
        target_root = target_root.parent

    for f in result.findings:
        # Register rule if not already present
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": f.severity.sarif_level},
                "help": {
                    "text": f"Remediation: {f.remediation}",
                    "markdown": f"**Remediation:** {f.remediation}",
                },
                "properties": {
                    "tags": [f.category.value.lower(), "security", "devsecops"],
                    "cwe": [f.cwe_id] if f.cwe_id else [],
                },
            }

        # Normalize path for SARIF (forward slashes)
        file_p = Path(f.file_path)
        try:
            rel_path = file_p.relative_to(target_root).as_posix()
        except ValueError:
            rel_path = file_p.as_posix()

        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {
                    "text": f"{f.title}: {f.description}. Fix: {f.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": f.line_number,
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PipeShield",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/example/pipeshield",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif_doc


def export_sarif(result: ScanResult, output_file: str | Path) -> None:
    """Export scan results as a SARIF 2.1.0 JSON file."""
    sarif_data = generate_sarif_dict(result)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
