from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern
from pipeshield.models import Category, Severity


@dataclass
class JsRule:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: Pattern[str]
    remediation: str
    cwe_id: str
    category: Category = Category.JS_RECON


JS_RULES: list[JsRule] = [
    JsRule(
        id="PS-JS-001",
        title="Hidden Administrative, Debug, or Internal API Endpoint in JS Bundle",
        description="A JavaScript/TypeScript file references an administrative, internal, debug, or server-status route. Attackers extract these endpoints during client-side reconnaissance to discover unprotected admin functionality, IDOR vectors, or WAF bypass routes.",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""['"`](\/(?:api\/v\d+\/)?(?:admin|internal|debug|private|actuator|swagger|graphql|server-status|phpinfo\.php|backup|config)(?:\/[a-zA-Z0-9_\-\/\?=&]*)?)['"`]""",
            re.IGNORECASE,
        ),
        remediation="Remove internal/debug endpoint paths from public client-side bundles, enforce strict server-side RBAC/authentication on all administrative routes, and split admin bundles from public builds.",
        cwe_id="CWE-200",
    ),
    JsRule(
        id="PS-JS-002",
        title="Unsafe DOM XSS Sink or Dynamic Code Execution (innerHTML / eval / document.write)",
        description="Detected dangerous client-side sink (`eval()`, `new Function()`, `document.write()`, `.innerHTML =`, or `dangerouslySetInnerHTML`). Unsanitized input reaching these sinks allows attackers to escalate HTML injection into full DOM-based Cross-Site Scripting (XSS).",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?:\b(?:eval|document\.write|document\.writeln)\s*\(|\bnew\s+Function\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\bdangerouslySetInnerHTML\b)"
        ),
        remediation="Use safe DOM APIs such as `textContent` or `innerText` instead of `innerHTML`, avoid `eval()` / `new Function()`, or sanitize untrusted HTML using DOMPurify before rendering.",
        cwe_id="CWE-79",
    ),
    JsRule(
        id="PS-JS-003",
        title="Exposed Production SourceMap Reference (sourceMappingURL)",
        description="The JavaScript bundle contains a `sourceMappingURL` directive pointing to a `.map` file. In production, exposed source maps allow attackers to reconstruct the full unminified source code, developer comments, and business logic.",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"//#\s*sourceMappingURL\s*=\s*\S+\.map\b", re.IGNORECASE),
        remediation="Disable public source map generation in production builds (e.g., `productionSourceMap: false` in Webpack/Vite) or restrict `.map` file access at the reverse proxy/CDN layer.",
        cwe_id="CWE-540",
    ),
    JsRule(
        id="PS-JS-004",
        title="Leaked Internal Origin IP or Staging Hostname in Client-Side JS",
        description="Hardcoded RFC1918 private IP address (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`) or internal hostname (`.internal`, `.corp`, `.local`, `.lan`) found in JavaScript code. This aids attackers in mapping internal infrastructure and bypassing CDN/WAF protection.",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""https?:\/\/(?:(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})|[a-zA-Z0-9._-]+\.(?:internal|corp|local|lan))\b""",
            re.IGNORECASE,
        ),
        remediation="Replace hardcoded internal IPs and staging URLs with environment-specific runtime configuration variables.",
        cwe_id="CWE-200",
    ),
    JsRule(
        id="PS-JS-005",
        title="Insecure Cross-Origin postMessage Wildcard ('*')",
        description="Using `postMessage(..., '*')` broadcasts sensitive client-side messages or tokens to any origin, allowing malicious iframes or windows to intercept data.",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\.postMessage\s*\([^,]+,\s*['\"`]\*['\"`]\s*\)"),
        remediation="Always specify the exact target origin URL (e.g., `https://app.example.com`) as the second argument to `postMessage` and validate `event.origin` in message listeners.",
        cwe_id="CWE-345",
    ),
]
