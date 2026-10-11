from pathlib import Path
from pipeshield.analyzers.js_analyzer import JsReconAnalyzer
from pipeshield.core.scanner import Scanner


def test_js_hidden_admin_endpoint(tmp_path: Path):
    js_file = tmp_path / "bundle.js"
    js_file.write_text(
        "const ADMIN_URL = '/api/v1/admin/users/export';\n"
        "fetch('/internal/debug/vars');\n",
        encoding="utf-8",
    )
    analyzer = JsReconAnalyzer()
    findings = analyzer.analyze_file(js_file, js_file.read_text(encoding="utf-8"))
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("PS-JS-001") == 2


def test_js_unsafe_dom_xss_sinks(tmp_path: Path):
    js_file = tmp_path / "ui.js"
    js_file.write_text(
        "document.getElementById('out').innerHTML = location.hash;\n"
        "const res = eval(userInput);\n",
        encoding="utf-8",
    )
    analyzer = JsReconAnalyzer()
    findings = analyzer.analyze_file(js_file, js_file.read_text(encoding="utf-8"))
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("PS-JS-002") == 2


def test_js_exposed_sourcemap(tmp_path: Path):
    js_file = tmp_path / "main.min.js"
    js_file.write_text(
        "console.log('minified');\n"
        "//# sourceMappingURL=main.min.js.map\n",
        encoding="utf-8",
    )
    analyzer = JsReconAnalyzer()
    findings = analyzer.analyze_file(js_file, js_file.read_text(encoding="utf-8"))
    assert any(f.rule_id == "PS-JS-003" for f in findings)


def test_js_leaked_internal_origin_ip(tmp_path: Path):
    js_file = tmp_path / "config.ts"
    js_file.write_text(
        "export const INTERNAL_BACKEND = 'http://10.0.20.51:8080/health';\n"
        "export const STAGING_HOST = 'https://auth.acme.internal/login';\n",
        encoding="utf-8",
    )
    analyzer = JsReconAnalyzer()
    findings = analyzer.analyze_file(js_file, js_file.read_text(encoding="utf-8"))
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("PS-JS-004") == 2


def test_js_insecure_postmessage_wildcard(tmp_path: Path):
    js_file = tmp_path / "iframe.js"
    js_file.write_text(
        "window.parent.postMessage({ jwt: sessionStorage.getItem('token') }, '*');\n",
        encoding="utf-8",
    )
    analyzer = JsReconAnalyzer()
    findings = analyzer.analyze_file(js_file, js_file.read_text(encoding="utf-8"))
    assert any(f.rule_id == "PS-JS-005" for f in findings)


def test_js_clean_bundle_no_false_positives(tmp_path: Path):
    js_file = tmp_path / "safe.js"
    js_file.write_text(
        "// eval('commented out code should not trigger')\n"
        "const api = 'https://api.example.com/v1/catalog';\n"
        "document.getElementById('title').textContent = 'Safe Text';\n"
        "window.parent.postMessage('ready', 'https://app.example.com');\n",
        encoding="utf-8",
    )
    scanner = Scanner()
    result = scanner.scan_path(js_file)
    assert len(result.findings) == 0
