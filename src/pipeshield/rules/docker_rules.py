from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern
from pipeshield.models import Severity, Category


@dataclass
class DockerRule:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: Optional[Pattern[str]] = None
    remediation: str = ""
    cwe_id: str = "CWE-250"
    category: Category = Category.DOCKER


DOCKER_RULES: list[DockerRule] = [
    DockerRule(
        id="PS-DOCK-001",
        title="Container runs as root (missing non-root USER)",
        description="The Dockerfile does not define a non-root USER instruction or explicitly specifies USER root. Processes inside the container run with root UID 0.",
        severity=Severity.HIGH,
        remediation="Create a dedicated system user/group (e.g., `RUN addgroup -S appgroup && adduser -S appuser -G appgroup`) and switch to it using `USER appuser`.",
        cwe_id="CWE-250",
    ),
    DockerRule(
        id="PS-DOCK-002",
        title="Unpinned base image tag (:latest or no tag)",
        description="The base image uses the ':latest' tag or omits the tag entirely, which causes non-deterministic builds and introduces untested upstream vulnerabilities.",
        severity=Severity.HIGH,
        pattern=re.compile(r"^\s*FROM\s+([^\s:]+)(?::latest)?(?:\s+AS\s+\w+)?$", re.IGNORECASE),
        remediation="Pin the base image to a specific immutable semantic version or SHA256 digest, e.g., `FROM python:3.12.3-slim-bookworm` or `FROM alpine@sha256:...`.",
        cwe_id="CWE-1104",
    ),
    DockerRule(
        id="PS-DOCK-003",
        title="Sensitive credential passed via ENV or ARG",
        description="A secret, token, key, or password is baked into an ENV or ARG instruction. These values persist in image layer metadata and are visible via `docker history`.",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"^\s*(?:ENV|ARG)\s+.*?(?:password|secret|token|api[_-]?key|private[_-]?key|aws_access|auth[_-]?token)[^\s=]*\s*=",
            re.IGNORECASE,
        ),
        remediation="Use BuildKit secret mounts (`RUN --mount=type=secret,id=mysecret ...`) or inject runtime environment variables instead of hardcoding in Dockerfile.",
        cwe_id="CWE-798",
    ),
    DockerRule(
        id="PS-DOCK-004",
        title="Unverified download and shell execution (curl/wget | sh)",
        description="The RUN instruction pipes remote network content directly into a shell interpreter (`curl ... | sh` or `wget ... | bash`) without checksum verification.",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        remediation="Download scripts to a temporary file, verify their cryptographic hash (e.g. `sha256sum -c`), and execute only after integrity verification.",
        cwe_id="CWE-494",
    ),
    DockerRule(
        id="PS-DOCK-005",
        title="Use of ADD instead of COPY for local files",
        description="`ADD` has unexpected side effects: it extracts tar archives automatically and accepts remote URLs. Best practice is to use `COPY` for local files.",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"^\s*ADD\s+(?!https?://|\w+://)", re.IGNORECASE),
        remediation="Replace `ADD` with `COPY` unless you explicitly require tar extraction capabilities.",
        cwe_id="CWE-668",
    ),
    DockerRule(
        id="PS-DOCK-006",
        title="Missing HEALTHCHECK instruction",
        description="The Dockerfile does not define a HEALTHCHECK instruction. Orchestrators cannot independently detect when a containerized service hangs or crashes.",
        severity=Severity.LOW,
        remediation="Add a `HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/health || exit 1` instruction.",
        cwe_id="CWE-754",
    ),
    DockerRule(
        id="PS-DOCK-007",
        title="Sudo package installed in container",
        description="Installing `sudo` inside a container introduces unnecessary privilege escalation utilities.",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:apt-get|apk|yum|dnf)\s+install\b.*(?:\s|^)sudo(?:\s|$)", re.IGNORECASE),
        remediation="Remove `sudo`. Configure least-privilege users without privilege escalation tools inside container images.",
        cwe_id="CWE-250",
    ),
]
