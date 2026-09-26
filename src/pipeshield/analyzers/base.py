from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from pipeshield.models import Finding


class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers in PipeShield."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @abstractmethod
    def can_handle(self, file_path: Path) -> bool:
        """Return True if this analyzer should inspect the given file."""
        pass

    @abstractmethod
    def analyze_file(self, file_path: Path, content: str) -> list[Finding]:
        """Analyze file content and return any security findings."""
        pass
