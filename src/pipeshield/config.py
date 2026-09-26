from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from pipeshield.models import Finding, Severity


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


@dataclass
class Config:
    fail_on: Severity = Severity.HIGH
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: set[str] = field(default_factory=set)
    rule_path_ignores: dict[str, list[str]] = field(default_factory=dict)
    entropy_threshold: float = 3.8
    skip_git_ignored: bool = True

    def should_ignore_file(self, file_path: Path, root_dir: Path) -> bool:
        """Check if file matches any ignored directory or ignore glob pattern."""
        try:
            rel_path = file_path.relative_to(root_dir).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()

        # Check default ignore directory components
        for part in file_path.parts:
            if part in DEFAULT_IGNORE_DIRS:
                return True

        # Check explicit ignore paths / globs
        for pattern in self.ignore_paths:
            pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True

        return False

    def is_finding_ignored(self, finding: Finding, root_dir: Path) -> bool:
        """Check if finding is explicitly suppressed by rule ID or rule:path pair."""
        if finding.rule_id in self.ignore_rules:
            return True

        if finding.rule_id in self.rule_path_ignores:
            file_p = Path(finding.file_path)
            try:
                rel_path = file_p.relative_to(root_dir).as_posix()
            except ValueError:
                rel_path = file_p.as_posix()

            for pattern in self.rule_path_ignores[finding.rule_id]:
                pattern = pattern.replace("\\", "/")
                if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_p.name, pattern):
                    return True

        return False

    @classmethod
    def load_from_directory(cls, directory: Path) -> Config:
        """Load configuration from .pipeshield-ignore in the given directory if present."""
        config = cls()
        ignore_file = directory / ".pipeshield-ignore"
        if not ignore_file.is_file():
            return config

        try:
            with open(ignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Targeted rule:path format, e.g. "PS-DOCK-001:Dockerfile.dev"
                    if ":" in line and line.startswith("PS-"):
                        rule_id, path_pattern = line.split(":", 1)
                        rule_id = rule_id.strip()
                        path_pattern = path_pattern.strip()
                        if rule_id not in config.rule_path_ignores:
                            config.rule_path_ignores[rule_id] = []
                        config.rule_path_ignores[rule_id].append(path_pattern)

                    # Global rule suppression, e.g. "PS-SEC-009"
                    elif line.startswith("PS-"):
                        config.ignore_rules.add(line.strip())

                    # Path/glob ignore, e.g. "tests/fixtures/*"
                    else:
                        config.ignore_paths.append(line)
        except Exception:
            pass

        return config
