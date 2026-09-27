from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from pipeshield.models import ScanResult, Severity


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PipeShield Security Audit Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --critical: #f85149;
      --high: #ff7b72;
      --medium: #d29922;
      --low: #3fb950;
      --info: #58a6ff;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 32px 24px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }

    /* Header */
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; flex-wrap: wrap; gap: 16px; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .logo-badge { background: linear-gradient(135deg, #1f6feb, #8957e5); color: #fff; font-weight: 800; font-size: 22px; padding: 8px 16px; border-radius: 8px; letter-spacing: 1px; }
    .brand-title h1 { font-size: 24px; font-weight: 700; color: #fff; }
    .brand-title p { font-size: 13px; color: var(--text-muted); }
    .status-badge { padding: 8px 16px; border-radius: 20px; font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-failed { background: rgba(248, 81, 73, 0.15); color: var(--critical); border: 1px solid var(--critical); }
    .status-passed { background: rgba(63, 185, 80, 0.15); color: var(--low); border: 1px solid var(--low); }

    /* Meta bar */
    .meta-bar { display: flex; gap: 24px; background: var(--card-bg); padding: 14px 20px; border-radius: 8px; border: 1px solid var(--border); font-size: 13px; margin-bottom: 28px; flex-wrap: wrap; }
    .meta-item strong { color: #fff; }

    /* Metric Cards Grid */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .metric-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
    .metric-value { font-size: 36px; font-weight: 800; margin-bottom: 4px; }
    .metric-label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-weight: 600; }
    .c-crit { color: var(--critical); }
    .c-high { color: var(--high); }
    .c-med { color: var(--medium); }
    .c-low { color: var(--low); }
    .c-total { color: #fff; }

    /* Filters & Search */
    .controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 16px; flex-wrap: wrap; }
    .filter-tabs { display: flex; gap: 8px; }
    .filter-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text-muted); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }
    .filter-btn:hover { border-color: var(--accent); color: #fff; }
    .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .search-box { background: var(--card-bg); border: 1px solid var(--border); color: #fff; padding: 8px 14px; border-radius: 6px; font-size: 13px; width: 280px; outline: none; }
    .search-box:focus { border-color: var(--accent); }

    /* Findings List */
    .findings-container { display: flex; flex-direction: column; gap: 14px; }
    .finding-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 18px 20px; transition: transform 0.1s, border-color 0.2s; border-left: 4px solid var(--border); }
    .finding-card:hover { border-color: #58a6ff; }
    .finding-card.sev-CRITICAL { border-left-color: var(--critical); }
    .finding-card.sev-HIGH { border-left-color: var(--high); }
    .finding-card.sev-MEDIUM { border-left-color: var(--medium); }
    .finding-card.sev-LOW { border-left-color: var(--low); }

    .card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; gap: 12px; }
    .rule-info { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .sev-pill { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 12px; text-transform: uppercase; }
    .pill-CRITICAL { background: rgba(248, 81, 73, 0.2); color: var(--critical); }
    .pill-HIGH { background: rgba(255, 123, 114, 0.2); color: var(--high); }
    .pill-MEDIUM { background: rgba(210, 153, 34, 0.2); color: var(--medium); }
    .pill-LOW { background: rgba(63, 185, 80, 0.2); color: var(--low); }
    .rule-id { font-family: monospace; font-size: 13px; font-weight: 700; color: var(--accent); }
    .cwe-tag { font-size: 11px; color: var(--text-muted); background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    .file-loc { font-family: monospace; font-size: 12px; color: var(--text-muted); background: #21262d; padding: 3px 8px; border-radius: 4px; }

    .card-title { font-size: 15px; font-weight: 600; color: #fff; margin-bottom: 8px; }
    .card-desc { font-size: 13px; color: var(--text-muted); margin-bottom: 12px; }

    .snippet-box { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; color: #e6edf3; overflow-x: auto; margin-bottom: 10px; white-space: pre-wrap; word-break: break-all; }
    .remediation-box { background: rgba(63, 185, 80, 0.08); border: 1px solid rgba(63, 185, 80, 0.3); border-radius: 6px; padding: 10px 14px; font-size: 13px; color: #7ee787; display: flex; gap: 8px; align-items: flex-start; }
    .remediation-box strong { color: #fff; }

    .no-findings { text-align: center; padding: 60px 20px; background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border); }
    .no-findings h2 { color: var(--low); margin-bottom: 8px; font-size: 20px; }

    footer { text-align: center; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 12px; }
    footer a { color: var(--accent); text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="logo-badge">PipeShield</div>
        <div class="brand-title">
          <h1>Security Audit Dashboard</h1>
          <p>Next-Gen DevSecOps Static Analysis & Secret Detection</p>
        </div>
      </div>
      <div>
        <span class="status-badge __STATUS_CLASS__">__STATUS_LABEL__</span>
      </div>
    </header>

    <div class="meta-bar">
      <div class="meta-item">Target: <strong>__TARGET_PATH__</strong></div>
      <div class="meta-item">Generated: <strong>__TIMESTAMP__</strong></div>
      <div class="meta-item">Duration: <strong>__DURATION__ ms</strong></div>
      <div class="meta-item">Files Scanned: <strong>__FILES_SCANNED__</strong></div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value c-total">__TOTAL_FINDINGS__</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="metric-card">
        <div class="metric-value c-crit">__CRITICAL_COUNT__</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value c-high">__HIGH_COUNT__</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card">
        <div class="metric-value c-med">__MEDIUM_COUNT__</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card">
        <div class="metric-value c-low">__LOW_COUNT__</div>
        <div class="metric-label">Low</div>
      </div>
    </div>

    <div class="controls">
      <div class="filter-tabs">
        <button class="filter-btn active" onclick="filterSeverity('ALL')">All (__TOTAL_FINDINGS__)</button>
        <button class="filter-btn" onclick="filterSeverity('CRITICAL')">Critical (__CRITICAL_COUNT__)</button>
        <button class="filter-btn" onclick="filterSeverity('HIGH')">High (__HIGH_COUNT__)</button>
        <button class="filter-btn" onclick="filterSeverity('MEDIUM')">Medium (__MEDIUM_COUNT__)</button>
        <button class="filter-btn" onclick="filterSeverity('LOW')">Low (__LOW_COUNT__)</button>
      </div>
      <input type="text" id="searchInput" class="search-box" placeholder="Search rules, files, snippets..." onkeyup="searchFindings()">
    </div>

    <div class="findings-container" id="findingsContainer">
      __FINDINGS_HTML__
    </div>

    <footer>
      Generated automatically by <a href="https://github.com/example/pipeshield" target="_blank">PipeShield DevSecOps Scanner</a> | OASIS SARIF 2.1.0 Compatible
    </footer>
  </div>

  <script>
    let currentFilter = 'ALL';

    function filterSeverity(sev) {
      currentFilter = sev;
      document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.textContent.toUpperCase().includes(sev));
      });
      applyFilters();
    }

    function searchFindings() {
      applyFilters();
    }

    function applyFilters() {
      const query = document.getElementById('searchInput').value.toLowerCase();
      const cards = document.querySelectorAll('.finding-card');

      cards.forEach(card => {
        const cardSev = card.getAttribute('data-severity');
        const cardText = card.textContent.toLowerCase();

        const matchesFilter = (currentFilter === 'ALL' || cardSev === currentFilter);
        const matchesSearch = !query || cardText.includes(query);

        if (matchesFilter && matchesSearch) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>
"""


def generate_html_report(result: ScanResult) -> str:
    """Generate a modern, standalone HTML Security Dashboard report."""
    summary = result.summary
    is_failed = summary.failed

    status_class = "status-failed" if is_failed else "status-passed"
    status_label = "Policy Failed" if is_failed else "Scan Clean"

    # Render finding cards
    if not result.findings:
        findings_html = """
        <div class="no-findings">
          <h2>[+] Repository is Clean!</h2>
          <p>No security vulnerabilities, credential leaks, or container misconfigurations were detected.</p>
        </div>
        """
    else:
        cards: list[str] = []
        for f in result.findings:
            rel_file = html.escape(Path(f.file_path).name)
            loc = f"{rel_file}:{f.line_number}"
            cwe = f'<span class="cwe-tag">{html.escape(f.cwe_id)}</span>' if f.cwe_id else ""
            rule_id = html.escape(f.rule_id)
            title = html.escape(f.title)
            desc = html.escape(f.description)
            snippet = html.escape(f.snippet)
            remediation = html.escape(f.remediation)
            sev = f.severity.value

            card = f"""
            <div class="finding-card sev-{sev}" data-severity="{sev}">
              <div class="card-header">
                <div class="rule-info">
                  <span class="sev-pill pill-{sev}">{sev}</span>
                  <span class="rule-id">{rule_id}</span>
                  {cwe}
                </div>
                <div class="file-loc">{loc}</div>
              </div>
              <div class="card-title">{title}</div>
              <div class="card-desc">{desc}</div>
              <div class="snippet-box">{snippet}</div>
              <div class="remediation-box">
                <div><strong>Fix:</strong> {remediation}</div>
              </div>
            </div>
            """
            cards.append(card)
        findings_html = "\n".join(cards)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    output = (
        HTML_TEMPLATE.replace("__STATUS_CLASS__", status_class)
        .replace("__STATUS_LABEL__", status_label)
        .replace("__TARGET_PATH__", html.escape(result.target_path))
        .replace("__TIMESTAMP__", now_str)
        .replace("__DURATION__", f"{summary.scan_duration_ms:.2f}")
        .replace("__FILES_SCANNED__", str(summary.scanned_files))
        .replace("__TOTAL_FINDINGS__", str(summary.total_findings))
        .replace("__CRITICAL_COUNT__", str(summary.critical_count))
        .replace("__HIGH_COUNT__", str(summary.high_count))
        .replace("__MEDIUM_COUNT__", str(summary.medium_count))
        .replace("__LOW_COUNT__", str(summary.low_count))
        .replace("__FINDINGS_HTML__", findings_html)
    )

    return output


def export_html(result: ScanResult, output_file: str | Path) -> None:
    """Export scan results as a self-contained interactive HTML report."""
    html_content = generate_html_report(result)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
