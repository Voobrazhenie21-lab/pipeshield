from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        levels = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels[self]

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level >= other.level

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level > other.level

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level <= other.level

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.level < other.level

    @property
    def color(self) -> str:
        colors = {
            Severity.INFO: "blue",
            Severity.LOW: "cyan",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "bright_red",
            Severity.CRITICAL: "bold red",
        }
        return colors[self]

    @property
    def sarif_level(self) -> str:
        """Map to SARIF 2.1.0 level: error, warning, note, none."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        if self == Severity.LOW:
            return "note"
        return "none"


class Category(str, Enum):
    SECRETS = "SECRETS"
    DOCKER = "CONTAINER"
    CICD = "CI/CD SUPPLY CHAIN"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    snippet: str
    remediation: str
    cwe_id: Optional[str] = None


@dataclass
class ScanSummary:
    scanned_files: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration_ms: float = 0.0
    failed: bool = False


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    target_path: str = "."
