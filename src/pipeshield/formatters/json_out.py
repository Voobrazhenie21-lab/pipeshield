from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from pipeshield.models import ScanResult


def export_json(result: ScanResult, output_file: str | Path) -> None:
    """Export scan results as human and machine-readable JSON."""
    data = {
        "target_path": result.target_path,
        "summary": asdict(result.summary),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "snippet": f.snippet,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
            }
            for f in result.findings
        ],
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
