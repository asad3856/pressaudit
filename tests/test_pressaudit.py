"""Tests for PressAudit, against a local mock WordPress site.

No real site is ever contacted: the mock server runs on localhost and
serves canned WordPress-like responses.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pressaudit import __version__, vulndb, wpscan
from pressaudit.cli import main
from pressaudit.report import format_html, format_json, format_text
from pressaudit.scanner import Scanner, scan_url
from pressaudit.updatedb import update_db

HOME = """<html><head>
<meta name="generator" content="WordPress 4.7.1" />
<link rel="stylesheet" href="/wp-content/plugins/revslider/css/style.css" />
<link rel="stylesheet" href="/wp-content/plugins/akismet/akismet.css" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css" />
<script src="/wp-includes/js/wp-embed.min.js"></script>
</head><body>hello</body></html>"""

README_HTML = "<html><head><title>WordPress 4.7.1</title></head><body>Version 4.7.1</body></html>"
REVSLIDER_README = "=== Slider Revolution ===\nStable tag: 4.1.4\n"
AKISMET_README = "=== Akismet ===\nStable tag: 5.0\n"
THEME_STYLE = "/*\nTheme Name: Twenty Twenty-One\nVersion: 1.0\n*/"
REST_INDEX = json.dumps({"namespaces": ["wp/v2", "oembed/1.0"]})
REST_USERS = json.dumps([
    {"id": 1, "slug": "admin", "name": "admin"},
    {"id": 2, "slug": "editor", "name": "editor"},
])
XMLRPC = "XML-RPC server accepts POST requests only."
DEBUG_LOG = "[01-Jan-2026] PHP Warning: something in /var/www/html/wp-content/plugins/x.php on line 3\n"
UPLOADS_LISTING = "<html><head><title>Index of /wp-content/uploads/</title></head></html>"
REGISTER = "<html><body><form>Register for this site</form></body></html>"
LOGIN = "<html><body><form id=\"loginform\">Log In</form></body></html>"
GIT_HEAD = "ref: refs/heads/main\n"
ENV_FILE = "DB_PASSWORD=secret123\nWP_ENV=production\n"
INSTALL_PAGE = "<html><body><h1>Welcome to WordPress installation</h1></body></html>"


class MockWPHandler(BaseHTTPRequestHandler):
    seen_cookies = []

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        MockWPHandler.seen_cookies.append(self.headers.get("Cookie"))
        routes = {
            "/": (200, HOME),
            "/readme.html": (200, README_HTML),
            "/wp-json/": (200, REST_INDEX, "application/json"),
            "/wp-json/wp/v2/users": (200, REST_USERS, "application/json"),
            "/wp-content/plugins/revslider/readme.txt": (200, REVSLIDER_README, "text/plain"),
            "/wp-content/plugins/akismet/readme.txt": (200, AKISMET_README, "text/plain"),
            "/wp-content/themes/twentytwentyone/style.css": (200, THEME_STYLE, "text/css"),
            "/xmlrpc.php": (405, XMLRPC),
            "/wp-content/debug.log": (200, DEBUG_LOG, "text/plain"),
            "/wp-content/uploads/": (200, UPLOADS_LISTING),
            "/wp-login.php?action=register": (200, REGISTER),
            "/wp-login.php": (200, LOGIN),
            "/.git/HEAD": (200, GIT_HEAD, "text/plain"),
            "/.env": (200, ENV_FILE, "text/plain"),
            "/wp-admin/install.php": (200, INSTALL_PAGE),
            "/license.txt": (200, "WordPress License\n"),
        }
        if self.path == "/?author=1":
            self.send_response(302)
            self.send_header("Location", "/author/admin/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        route = routes.get(self.path)
        if route is None:
            self._send(404, "not found")
            return
        self._send(*route)

    do_HEAD = do_GET


class NonWPHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        data = b"<html><body>just a page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(vulndb.parse_version("6.2.1"), (6, 2, 1))
        self.assertEqual(vulndb.parse_version("4.7"), (4, 7, 0))
        self.assertIsNone(vulndb.parse_version("abc"))

    def test_compare(self):
        self.assertTrue(vulndb.version_lte("4.7.1", "4.7.1"))
        self.assertTrue(vulndb.version_lte("4.7.0", "4.7.1"))
        self.assertFalse(vulndb.version_lte("4.7.2", "4.7.1"))
        self.assertTrue(vulndb.version_lt("5.9", "6.0"))
        self.assertFalse(vulndb.version_lt("6.0", "6.0"))

    def test_core_vulns(self):
        self.assertEqual(len(vulndb.core_vulns_for("4.7.1")), 2)
        self.assertEqual(vulndb.core_vulns_for("6.5"), [])

    def test_plugin_vulns(self):
        self.assertEqual(len(vulndb.plugin_vulns_for("revslider", "4.1.4")), 1)
        self.assertEqual(vulndb.plugin_vulns_for("revslider", "4.2"), [])
        self.assertEqual(vulndb.plugin_vulns_for("akismet", "5.0"), [])

    def test_json_db_entries(self):
        # Verified entries from the JSON database (checked 8 Nov 2026).
        core, slugs, entries = vulndb.db_stats()
        self.assertEqual(core, 2)
        self.assertGreaterEqual(entries, 6)
        self.assertEqual(len(vulndb.plugin_vulns_for("contact-form-7", "5.3.1")), 1)
        self.assertEqual(vulndb.plugin_vulns_for("contact-form-7", "5.3.2"), [])
        self.assertEqual(len(vulndb.plugin_vulns_for("wp-file-manager", "6.8")), 1)
        self.assertEqual(vulndb.plugin_vulns_for("wp-file-manager", "6.9"), [])

    def test_fixed_in_conversion(self):
        self.assertEqual(vulndb._fixed_in_to_max("5.3.2"), "5.3.1")
        self.assertEqual(vulndb._fixed_in_to_max("6.9"), "6.8.999")
        self.assertIsNone(vulndb._fixed_in_to_max("0.0.0"))


class MockWPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = start_server(MockWPHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_full_scan(self):
        findings, scanner = scan_url(self.url, timeout=5, delay=0)
        by_id = {}
        for finding in findings:
            by_id.setdefault(finding.check_id, []).append(finding)
        self.assertTrue(scanner.is_wordpress)
        self.assertEqual(scanner.core_version, "4.7.1")
        # Core CVE + EOL
        self.assertIn("PA004", by_id)
        self.assertTrue(any("CVE-2017-5487" in f.evidence for f in by_id["PA004"]))
        self.assertIn("PA003", by_id)
        # readme disclosure
        self.assertIn("PA010", by_id)
        # REST user enumeration
        self.assertIn("PA012", by_id)
        self.assertTrue(any("admin" in f.evidence for f in by_id["PA012"]))
        # Author redirect enumeration
        self.assertIn("PA013", by_id)
        # revslider vulnerable, akismet not flagged
        self.assertIn("PA020", by_id)
        self.assertTrue(any("revslider" in f.title for f in by_id["PA020"]))
        self.assertFalse(any("akismet" in f.title for f in by_id.get("PA020", [])))
        # exposures
        self.assertIn("PA030", by_id)  # xmlrpc
        self.assertIn("PA031", by_id)  # debug.log
        self.assertIn("PA033", by_id)  # uploads listing
        self.assertIn("PA034", by_id)  # open registration
        # no wp-config backup in the mock
        self.assertNotIn("PA032", by_id)
        # plain HTTP + missing headers
        self.assertIn("PA040", by_id)
        self.assertIn("PA041", by_id)
        # plugins/themes detected
        self.assertIn("revslider", scanner.plugins)
        self.assertEqual(scanner.plugins["revslider"], "4.1.4")
        self.assertEqual(scanner.plugins["akismet"], "5.0")
        self.assertIn("twentytwentyone", scanner.themes)

    def test_report_formats(self):
        findings, scanner = scan_url(self.url, timeout=5, delay=0)
        text = format_text(self.url, findings, scanner.core_version)
        self.assertIn("WordPress core: 4.7.1", text)
        self.assertIn("PA004", text)
        data = json.loads(format_json(self.url, findings, scanner))
        self.assertTrue(data["wordpress"])
        self.assertEqual(data["core_version"], "4.7.1")
        self.assertTrue(any(f["id"] == "PA004" for f in data["findings"]))
        html = format_html(self.url, findings, scanner)
        self.assertIn("<title>PressAudit report:", html)
        self.assertIn("PA004", html)
        self.assertIn("WordPress core:", html)

    def test_new_exposure_checks(self):
        findings, _ = scan_url(self.url, timeout=5, delay=0)
        by_id = {}
        for finding in findings:
            by_id.setdefault(finding.check_id, []).append(finding)
        # Install page reachable
        self.assertIn("PA036", by_id)
        # .git/HEAD and .env both exposed -> two PA037 findings
        self.assertEqual(len(by_id.get("PA037", [])), 2)
        self.assertTrue(any("/.git/HEAD" in f.evidence for f in by_id["PA037"]))
        self.assertTrue(any("/.env" in f.evidence for f in by_id["PA037"]))
        # Server header discloses a version (BaseHTTP sends one)
        self.assertIn("PA051", by_id)
        # TLS checks only run on https targets
        self.assertNotIn("PA050", by_id)

    def test_cookie_is_sent(self):
        MockWPHandler.seen_cookies.clear()
        scan_url(self.url, timeout=5, delay=0,
                 cookie="wordpress_logged_in_x=test123")
        self.assertIn("wordpress_logged_in_x=test123",
                      MockWPHandler.seen_cookies)

    def test_wpscan_skipped_without_key(self):
        _, scanner = scan_url(self.url, timeout=5, delay=0)
        self.assertFalse(scanner.wpscan_used)
        self.assertEqual(wpscan.lookup("plugins", "revslider", "4.1.4", ""), [])

    def test_version(self):
        self.assertEqual(__version__, "0.3.0")

    def test_parallel_matches_sequential(self):
        seq_findings, seq_scanner = scan_url(self.url, timeout=5, delay=0,
                                             workers=1)
        par_findings, par_scanner = scan_url(self.url, timeout=5, delay=0,
                                             workers=10)
        self.assertEqual({f.check_id for f in seq_findings},
                         {f.check_id for f in par_findings})
        self.assertEqual(len(seq_findings), len(par_findings))
        self.assertEqual(seq_scanner.plugins, par_scanner.plugins)
        self.assertEqual(seq_scanner.themes, par_scanner.themes)

    def test_deep_mode_probes_more(self):
        _, fast = scan_url(self.url, timeout=5, delay=0, mode="fast")
        _, deep = scan_url(self.url, timeout=5, delay=0, mode="deep",
                           max_requests=400)
        self.assertGreater(deep.requests_made, fast.requests_made)
        self.assertGreater(len(deep.plugins), 0)

    def test_update_db_with_mocked_api(self):
        import os
        import tempfile
        from pressaudit import wpscan as wpscan_mod

        def fake_fetch(url, api_key, timeout=10):
            if "plugins/revslider" in url:
                return {"vulnerabilities": [
                    {"title": "Test Vuln", "fixed_in": "2.0",
                     "references": {"cve": ["2020-1234"]}}]}
            return {"vulnerabilities": []}

        original = wpscan_mod.fetch_json
        wpscan_mod.fetch_json = fake_fetch
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "vulndb.json")
                fetched, total, path = update_db(
                    "fake-key", out_path=out, delay=0)
                self.assertGreaterEqual(fetched, 50)
                self.assertEqual(path, out)
                with open(out, encoding="utf-8") as handle:
                    data = json.load(handle)
                # Curated entries kept + the mocked one merged in.
                self.assertGreaterEqual(total, 9)
                revslider = data["plugins"].get("revslider", [])
                self.assertTrue(any(e.get("fixed_in") == "2.0"
                                    for e in revslider))
                self.assertTrue(any(e.get("max_affected") == "4.1.4"
                                    for e in revslider))
        finally:
            wpscan_mod.fetch_json = original

    def test_update_db_requires_key(self):
        with self.assertRaises(ValueError):
            update_db("")
        self.assertEqual(main(["update-db", "--wpscan-api-key", ""]), 2)

    def test_cli_exit_code(self):
        self.assertEqual(main(["scan", self.url, "--quiet"]), 1)

    def test_non_wordpress(self):
        server, url = start_server(NonWPHandler)
        try:
            findings, scanner = scan_url(url, timeout=5, delay=0)
            self.assertFalse(scanner.is_wordpress)
            self.assertTrue(any(f.check_id == "PA001" for f in findings))
            # Exit code is 1, not 0: the mock URL is plain HTTP, so the
            # medium PA040 finding fires even though it is not WordPress.
            self.assertEqual(main(["scan", url, "--quiet"]), 1)
        finally:
            server.shutdown()

    def test_unreachable(self):
        with self.assertRaises(Exception):
            scan_url("http://127.0.0.1:1", timeout=2)


class WPScanTests(unittest.TestCase):
    def test_build_url(self):
        self.assertEqual(wpscan.build_url("core"),
                         "https://wpscan.com/api/v3/wordpresses")
        self.assertEqual(wpscan.build_url("plugins", "revslider"),
                         "https://wpscan.com/api/v3/plugins/revslider")

    def test_parse_vulnerabilities(self):
        data = {"vulnerabilities": [
            {"title": "RevSlider < 4.2 - Arbitrary File Upload",
             "fixed_in": "4.2",
             "references": {"cve": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9735"]}},
            {"title": "Old issue", "fixed_in": "4.0", "references": {}},
            {"title": "No fix version", "references": {}},
        ]}
        results = wpscan.parse_vulnerabilities(data, "4.1.4")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["fixed_in"], "4.2")
        self.assertIn("CVE-2014-9735", results[0]["cve"])
        # Already fixed: nothing returned
        self.assertEqual(wpscan.parse_vulnerabilities(data, "4.2"), [])
        self.assertEqual(wpscan.parse_vulnerabilities({}, "4.1.4"), [])
        self.assertEqual(wpscan.parse_vulnerabilities(None, "4.1.4"), [])


if __name__ == "__main__":
    unittest.main()
