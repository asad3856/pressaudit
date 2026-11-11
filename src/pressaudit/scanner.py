"""PressAudit scanner: detection-only WordPress security checks.

Standard library only. The scanner only issues ordinary HTTP GET/HEAD
requests against the target and reads the responses; it never posts
exploit payloads, never uploads anything, never attempts logins, and
never brute-forces credentials. Only scan sites you own or have explicit
permission to test.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import vulndb, wpscan

USER_AGENT = "PressAudit/0.4.0 (+https://github.com/asad3856/pressaudit)"
MAX_BODY = 1_000_000
POLITE_DELAY = 0.15

# Popular plugins probed for version disclosure (in addition to the ones
# discovered on the homepage and the high-risk list below).
POPULAR_PLUGINS = [
    "akismet",
    "contact-form-7",
    "woocommerce",
    "wordpress-seo",
    "jetpack",
    "elementor",
    "wordfence",
    "all-in-one-seo-pack",
    "wpforms-lite",
    "updraftplus",
    "duplicator",
    "really-simple-ssl",
    "w3-total-cache",
    "wp-super-cache",
    "classic-editor",
    "advanced-custom-fields",
    "google-analytics-for-wordpress",
    "mailchimp-for-wp",
    "broken-link-checker",
    "wp-optimize",
    "smush",
    "nextgen-gallery",
    "tablepress",
    "cookie-notice",
    "wp-mail-smtp",
    "redirection",
    "wordfence",
    "limit-login-attempts-reloaded",
    "sucuri-scanner",
    "all-in-one-wp-migration",
    "site-kit-by-google",
    "woocommerce-services",
    "jetpack-boost",
    "wp-rocket",
    "imagify",
    "wp-fastest-cache",
    "better-wp-security",
    "wp-statistics",
    "monsterinsights",
    "optinmonster",
    "wpforms",
]

# Plugins historically linked to serious unauthenticated flaws; probed even
# when the homepage does not reference them.
HIGH_RISK_PLUGINS = [
    "revslider",
    "wp-mobile-detector",
    "wysija-newsletters",
    "gravityforms",
    "formcraft",
    "download-monitor",
    "wp-symposium",
    "sitepress-multilingual-cms",
    "slideshow-gallery",
    "wp-file-manager",
    "file-manager",
    "ninja-forms",
    "contact-form-7",
]

# Common themes probed for version disclosure.
COMMON_THEMES = [
    "twentytwentyfour",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "twentytwenty",
    "astra",
    "oceanwp",
    "generatepress",
    "hello-elementor",
    "storefront",
    "divi",
    "avada",
    "flatsome",
    "woodmart",
    "enfold",
    "betheme",
]

# Deep mode: a much larger probe list (~120 popular plugin slugs).
DEEP_PLUGINS = sorted(set(POPULAR_PLUGINS + HIGH_RISK_PLUGINS + [
    "user-role-editor", "members", "simple-history", "activity-log",
    "two-factor", "loginizer", "cerber", "all-in-one-wp-security-and-firewall",
    "shield-security", "backwpup", "blogvault", "wpvivid-backuprestore",
    "wp-staging", "wp-migrate-db", "better-search-replace", "rank-math",
    "seopress", "the-seo-framework", "amp", "mailpoet", "newsletter",
    "mailster", "fluent-smtp", "post-smtp", "regenerate-thumbnails",
    "ewww-image-optimizer", "shortpixel", "autoptimize", "asset-cleanup",
    "perfmatters", "hummingbird", "clearfy", "disable-comments",
    "login-lockdown", "wp-cerber", "solid-security", "patchstack",
    "wp-security-audit-log", "stream", "wp-activity-log",
    "error-log-monitor", "query-monitor", "debug-bar", "user-switching",
    "theme-check", "wordpress-importer", "custom-post-type-ui", "pods",
    "meta-box", "cmb2", "jet-engine", "divi-builder", "beaver-builder",
    "brizy", "wpbakery", "mailchimp-for-woocommerce",
    "woocommerce-gateway-stripe", "woocommerce-paypal-payments",
    "elementor-pro", "essential-addons-for-elementor",
    "happy-addons-for-elementor", "kadence-blocks", "spectra",
    "generateblocks", "gutenberg", "classic-widgets", "health-check",
    "disable-gutenberg", "enable-jquery-migrate-helper",
    "go-live-update-urls", "safe-redirect-manager", "seo-by-rank-math",
    "schema", "wp-schema-pro", "instant-articles",
    "facebook-for-woocommerce", "hubspot", "klaviyo", "omnisend",
    "constant-contact", "aweber", "getresponse", "sendgrid", "postmark",
    "mailgun", "wp-mail-logging", "email-log", "check-email",
    "wp-offload-media", "enable-media-replace", "tinypng", "re-smush",
    "optimole", "cache-enabler", "comet-cache", "hyper-cache",
    "swift-performance", "wp-disable", "no-self-ping",
    "limit-login-attempts", "wordfence-security", "ninja-firewall",
    "bbq-firewall", "malcare", "vaultpress", "jetpack-protect", "wp-2fa",
    "google-authenticator", "wordfence-login-security", "hide-my-wp",
    "wp-hide-security-enhancer", "bulletproof-security", "wp-fail2ban",
    "logbook", "wp-log-viewer", "debug-log", "aryos",
    "user-activity-log", "easy-wp-smtp", "slideshow-gallery",
    "wp-file-manager", "file-manager", "ninja-forms",
]))

# Deep mode themes.
DEEP_THEMES = sorted(set(COMMON_THEMES + [
    "twentynineteen", "twentyeighteen", "twentytwentyseventeen",
    "kadence", "blocksy", "neve", "customify", "sydney", "colormag",
    "zerif-lite", "evolve", "hueman", "responsive", "shapely", "illdy",
    "sparkling", "activello", "dazzling", "travelify", "hestia", "zakra",
    "popularfx", "understrap", "sage", "hello-theme", "one-page-express",
    "corporate", "pinbin",
]))

WP_CONFIG_BACKUPS = [
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.php.swp",
    "wp-config.php~",
    "wp-config.php.txt",
    ".wp-config.php.swp",
]

SECURITY_HEADERS = {
    "x-content-type-options": ("nosniff", "low",
        "Missing X-Content-Type-Options header"),
    "x-frame-options": (None, "low",
        "Missing X-Frame-Options header (clickjacking protection)"),
    "referrer-policy": (None, "low", "Missing Referrer-Policy header"),
    "content-security-policy": (None, "low",
        "Missing Content-Security-Policy header"),
}


class Finding:
    """One scanner finding."""

    def __init__(self, check_id, severity, title, detail, evidence="",
                 remediation="", refs=()):
        self.check_id = check_id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence
        self.remediation = remediation
        self.refs = list(refs)

    def to_dict(self):
        return {
            "id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "refs": self.refs,
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects (for the
    ?author=1 enumeration check, where the redirect itself is the signal)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FetchResult:
    def __init__(self, status, url, headers, body, final_url):
        self.status = status
        self.url = url
        self.headers = headers
        self.body = body
        self.final_url = final_url


class ScanError(Exception):
    """The target could not be reached or scanned."""


class Scanner:
    """Runs the PressAudit checks against one base URL."""

    def __init__(self, base_url, timeout=10, max_requests=250, delay=POLITE_DELAY,
                 cookie=None, wpscan_api_key=None, workers=10, mode="fast"):
        self.base_url = base_url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = "https://" + self.base_url
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self.cookie = cookie
        self.wpscan_api_key = wpscan_api_key
        self.workers = max(1, int(workers))
        self.mode = mode
        self._lock = threading.Lock()
        self.requests_made = 0
        self.findings = []
        self.is_wordpress = False
        self.core_version = None
        self.plugins = {}  # slug -> version or None
        self.themes = {}   # slug -> version or None
        self.wpscan_used = False

    # -- HTTP -------------------------------------------------------------
    def fetch(self, path, method="GET", data=None, follow_redirects=True):
        with self._lock:
            if self.requests_made >= self.max_requests:
                raise ScanError("request budget exhausted (%d)" % self.max_requests)
            self.requests_made += 1
        url = self.base_url + path if path.startswith("/") else path
        req = urllib.request.Request(url, method=method, data=data)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "text/html,application/json,*/*")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        if self.delay:
            time.sleep(self.delay)
        opener = None
        if not follow_redirects:
            opener = urllib.request.build_opener(_NoRedirect)
        try:
            if opener is not None:
                resp = opener.open(req, timeout=self.timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
            with resp:
                raw = resp.read(MAX_BODY + 1)[:MAX_BODY]
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return FetchResult(resp.status, url, headers,
                                   raw.decode("utf-8", "replace"),
                                   resp.geturl())
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_BODY + 1)[:MAX_BODY]
            headers = {k.lower(): v for k, v in exc.headers.items()}
            return FetchResult(exc.code, url, headers,
                               raw.decode("utf-8", "replace"), url)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ScanError("request to %s failed: %s" % (url, exc))

    def fetch_many(self, paths):
        """Fetch several paths concurrently (enumeration phase).

        Returns {path: FetchResult or None}. A failed request yields None
        instead of raising, so one dead probe never aborts the scan.
        With workers == 1 this is just sequential fetching.
        """
        if self.workers <= 1 or len(paths) <= 1:
            results = {}
            for path in paths:
                try:
                    results[path] = self.fetch(path)
                except ScanError:
                    results[path] = None
            return results
        results = {}
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.workers) as pool:
            futures = {pool.submit(self._safe_fetch, path): path
                       for path in paths}
            for future in concurrent.futures.as_completed(futures):
                results[futures[future]] = future.result()
        return results

    def _safe_fetch(self, path):
        try:
            return self.fetch(path)
        except ScanError:
            return None

    # -- helpers ----------------------------------------------------------
    def add(self, check_id, severity, title, detail, evidence="",
            remediation="", refs=()):
        self.findings.append(Finding(check_id, severity, title, detail,
                                     evidence, remediation, refs))

    @staticmethod
    def _version_from_text(text, patterns):
        for pattern in patterns:
            match = re.search(pattern, text or "", re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    # -- checks -----------------------------------------------------------
    def check_homepage(self):
        """Detect WordPress and fingerprint the core version."""
        home = self.fetch("/")
        if home.status >= 400:
            raise ScanError("homepage returned HTTP %d" % home.status)
        body = home.body
        signals = []
        if re.search(r'wp-content|wp-includes', body):
            signals.append("wp-content/wp-includes paths")
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress', body, re.I):
            signals.append("generator meta tag")
        if "/wp-json/" in body:
            signals.append("wp-json reference")
        if re.search(r'wp-embed\.min\.js|wp-block-library', body):
            signals.append("wp scripts/styles")
        self.is_wordpress = bool(signals)
        if not self.is_wordpress:
            self.add("PA001", "info", "Target does not look like WordPress",
                     "None of the usual WordPress markers were found on the "
                     "homepage, so WordPress-specific checks were skipped.",
                     evidence="homepage HTTP %d, no wp-content/wp-includes, "
                     "generator, or wp-json markers" % home.status,
                     remediation="If this is a WordPress site, check that "
                     "the URL is correct and reachable.")
            return home
        version = self._version_from_text(body, [
            r'content=["\']WordPress\s+([0-9][0-9a-zA-Z.\-]*)["\']',
            r'WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ])
        # Discover installed plugins/themes from homepage references.
        for slug in sorted(set(re.findall(r'wp-content/plugins/([a-z0-9\-_]+)/', body))):
            self.plugins.setdefault(slug, None)
        for slug in sorted(set(re.findall(r'wp-content/themes/([a-z0-9\-_]+)/', body))):
            self.themes.setdefault(slug, None)
        # readme.html often discloses the exact version.
        readme = self.fetch("/readme.html")
        if readme.status == 200:
            rv = self._version_from_text(readme.body, [
                r'Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            ])
            if rv:
                version = rv
            self.add("PA010", "low", "readme.html exposes the WordPress version",
                     "The WordPress readme file is publicly readable and "
                     "discloses the exact core version, which helps an "
                     "attacker pick matching exploits.",
                     evidence="GET /readme.html -> HTTP 200",
                     remediation="Delete readme.html (and license.txt) from "
                     "the web root, or block them in the web server config.")
        if version:
            self.core_version = version
            self.add("PA002", "info", "WordPress core version detected",
                     "Core version %s was fingerprinted." % version,
                     evidence="version %s" % version)
            if vulndb.version_lt(version, vulndb.CORE_EOL_BELOW):
                self.add("PA003", "high",
                         "WordPress core is end-of-life (below %s)" % vulndb.CORE_EOL_BELOW,
                         "WordPress %s no longer receives security updates, "
                         "so any new core vulnerability stays unpatched." % version,
                         evidence="version %s" % version,
                         remediation="Update WordPress core to a supported "
                         "release (6.x) and keep it updated.",
                         refs=["https://wordpress.org/about/requirements/"])
            for max_ver, cve, title, fix in vulndb.core_vulns_for(version):
                self.add("PA004", "high", title,
                         "Core version %s is affected (affects versions up to %s)."
                         % (version, max_ver),
                         evidence="%s affects <= %s" % (cve, max_ver),
                         remediation=fix,
                         refs=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve])
        return home

    def check_rest_api(self):
        """REST API availability and user enumeration."""
        index = self.fetch("/wp-json/")
        if index.status == 200:
            try:
                data = json.loads(index.body)
                namespaces = data.get("namespaces", [])
                if "wp/v2" in namespaces:
                    self.add("PA011", "info", "WordPress REST API is enabled",
                             "The REST API (wp/v2) is reachable.",
                             evidence="/wp-json/ -> HTTP 200, namespaces: %s"
                             % ", ".join(namespaces[:5]))
            except (ValueError, AttributeError):
                pass
        users = self.fetch("/wp-json/wp/v2/users")
        if users.status == 200:
            try:
                data = json.loads(users.body)
                if isinstance(data, list) and data:
                    names = [u.get("slug") or u.get("name") for u in data[:5]]
                    self.add("PA012", "medium",
                             "User enumeration via REST API",
                             "The REST API lists %d user(s), disclosing "
                             "usernames that can be used for login attempts."
                             % len(data),
                             evidence="users: %s" % ", ".join(str(n) for n in names),
                             remediation="Restrict /wp-json/wp/v2/users to "
                             "authenticated users, or disable the users "
                             "endpoint if it is not needed.")
            except ValueError:
                pass
        author = self.fetch("/?author=1", follow_redirects=False)
        location = author.headers.get("location", "")
        if author.status in (301, 302) and "/author/" in location:
            self.add("PA013", "low", "User enumeration via ?author=1 redirect",
                     "Requesting ?author=1 redirects to the author's archive "
                     "page, disclosing a username.",
                     evidence="redirects to %s" % location,
                     remediation="Block author enumeration or use a plugin "
                     "that stops the redirect.")

    def check_plugins_themes(self):
        """Probe plugin/theme versions and match the offline vuln DB.

        Probing is parallel (ThreadPoolExecutor) because it is the bulk of
        the scan's requests. Fast mode probes the discovered slugs plus the
        popular and high-risk lists; deep mode probes ~120 plugin slugs and
        ~40 themes.
        """
        if self.mode == "deep":
            plugin_slugs = sorted(set(list(self.plugins) + DEEP_PLUGINS))
            theme_slugs = sorted(set(list(self.themes) + DEEP_THEMES))
        else:
            plugin_slugs = sorted(set(list(self.plugins) + HIGH_RISK_PLUGINS
                                      + POPULAR_PLUGINS))
            theme_slugs = sorted(set(list(self.themes) + COMMON_THEMES))
        plugin_paths = ["/wp-content/plugins/%s/readme.txt" % slug
                        for slug in plugin_slugs]
        plugin_results = self.fetch_many(plugin_paths)
        for slug, path in zip(plugin_slugs, plugin_paths):
            readme = plugin_results.get(path)
            if readme is None or readme.status != 200:
                continue
            version = self._version_from_text(readme.body, [
                r'Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            ])
            self.plugins[slug] = version
            if version:
                for max_ver, note, title, fix in vulndb.plugin_vulns_for(slug, version):
                    self.add("PA020", "high", title,
                             "%s %s is affected (affects versions up to %s). %s"
                             % (slug, version, max_ver, note),
                             evidence="readme.txt Stable tag: %s" % version,
                             remediation=fix)
        theme_paths = ["/wp-content/themes/%s/style.css" % slug
                       for slug in theme_slugs]
        theme_results = self.fetch_many(theme_paths)
        for slug, path in zip(theme_slugs, theme_paths):
            style = theme_results.get(path)
            if style is None or style.status != 200:
                continue
            version = self._version_from_text(style.body, [
                r'Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            ])
            self.themes[slug] = version
        if self.plugins:
            found = ", ".join(
                "%s%s" % (s, " " + v if v else "")
                for s, v in sorted(self.plugins.items()))
            self.add("PA021", "info", "Plugins detected",
                     "Detected %d plugin(s)." % len(self.plugins),
                     evidence=found)
        if self.themes:
            found = ", ".join(
                "%s%s" % (s, " " + v if v else "")
                for s, v in sorted(self.themes.items()))
            self.add("PA022", "info", "Themes detected",
                     "Detected %d theme(s)." % len(self.themes),
                     evidence=found)

    def check_exposures(self):
        """Commonly exposed files and endpoints."""
        xmlrpc = self.fetch("/xmlrpc.php")
        if xmlrpc.status in (200, 405) and "XML-RPC server accepts POST" in xmlrpc.body:
            self.add("PA030", "medium", "XML-RPC is enabled",
                     "xmlrpc.php responds, which enables pingback abuse and "
                     "password-guessing amplification.",
                     evidence="GET /xmlrpc.php -> HTTP %d" % xmlrpc.status,
                     remediation="Disable XML-RPC if it is not needed "
                     "(e.g. with the 'Disable XML-RPC' approach in your "
                     "security plugin or server config), or rate-limit it.")
        debug = self.fetch("/wp-content/debug.log")
        if debug.status == 200 and debug.body.strip():
            self.add("PA031", "high", "debug.log is publicly readable",
                     "WordPress debug output is exposed and can leak file "
                     "paths, queries, and other internals.",
                     evidence="GET /wp-content/debug.log -> HTTP 200 (%d bytes)"
                     % len(debug.body),
                     remediation="Move debug.log outside the web root, "
                     "disable WP_DEBUG_LOG on production, or block the file.")
        for name in WP_CONFIG_BACKUPS:
            res = self.fetch("/" + name)
            if res.status == 200 and res.body.strip():
                self.add("PA032", "high",
                         "Backup of wp-config.php is publicly readable: %s" % name,
                         "A wp-config backup can leak database credentials "
                         "and secret keys.",
                         evidence="GET /%s -> HTTP 200" % name,
                         remediation="Delete backup copies of wp-config.php "
                         "from the web root immediately and rotate the "
                         "database password and salts.")
        uploads = self.fetch("/wp-content/uploads/")
        if uploads.status == 200 and "Index of" in uploads.body:
            self.add("PA033", "medium", "Directory listing enabled on uploads",
                     "The uploads directory lists its contents, exposing "
                     "file names and structure.",
                     evidence="GET /wp-content/uploads/ -> HTTP 200, Index of",
                     remediation="Disable directory listings (Options -Indexes) "
                     "in the web server config.")
        reg = self.fetch("/wp-login.php?action=register")
        if reg.status == 200 and re.search(r'Register|registration', reg.body, re.I):
            self.add("PA034", "low", "User registration is open",
                     "Anyone can register an account on this site.",
                     evidence="/wp-login.php?action=register -> HTTP 200",
                     remediation="Disable open registration (Settings > "
                     "General) unless the site needs it.")
        login = self.fetch("/wp-login.php")
        if login.status == 200:
            self.add("PA035", "info", "Login page is reachable",
                     "The WordPress login page is publicly reachable, as on "
                     "most WordPress sites.",
                     evidence="/wp-login.php -> HTTP 200",
                     remediation="Use strong passwords, limit login attempts, "
                     "and enable two-factor authentication.")

    def check_install_and_repo(self):
        """Fresh-install page and exposed repository/config files."""
        install = self.fetch("/wp-admin/install.php")
        if install.status == 200 and re.search(
                r"install\.php|Welcome to WordPress|installation", install.body, re.I):
            self.add("PA036", "high", "WordPress install page is reachable",
                     "wp-admin/install.php responds, which on a site without "
                     "a configured wp-config.php would allow a fresh install.",
                     evidence="GET /wp-admin/install.php -> HTTP 200",
                     remediation="Make sure wp-config.php exists and is "
                     "correct, and block install.php once the site is set up.")
        git = self.fetch("/.git/HEAD")
        if git.status == 200 and git.body.strip().startswith("ref:"):
            self.add("PA037", "high", "Git repository is publicly exposed",
                     "The .git directory is web-accessible, so the full "
                     "source history (including secrets committed by "
                     "mistake) can be downloaded.",
                     evidence="GET /.git/HEAD -> HTTP 200 (%s...)"
                     % git.body.strip()[:40],
                     remediation="Block .git (and other hidden files) in the "
                     "web server config, or move the repository out of the "
                     "web root.")
        env = self.fetch("/.env")
        if env.status == 200 and re.search(r"^[A-Z_]+=.{2,}", env.body, re.M):
            self.add("PA037", "high", ".env file is publicly readable",
                     "A .env file is web-accessible and can leak API keys, "
                     "passwords, and other secrets.",
                     evidence="GET /.env -> HTTP 200",
                     remediation="Move .env outside the web root and rotate "
                     "every secret it contained.")

    def check_tls(self):
        """TLS certificate validity (HTTPS targets only)."""
        if not self.base_url.startswith("https://"):
            return
        host = urllib.parse.urlparse(self.base_url).hostname
        if not host:
            return
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure:
                    cert = secure.getpeercert()
        except ssl.SSLCertVerificationError:
            self.add("PA050", "medium", "TLS certificate is not trusted",
                     "The site's TLS certificate failed verification "
                     "(self-signed, expired chain, or wrong hostname).",
                     evidence="certificate verification failed for %s" % host,
                     remediation="Install a valid certificate from a trusted "
                     "authority for the correct hostname.")
            return
        except (OSError, ssl.SSLError):
            return
        not_after = cert.get("notAfter")
        if not not_after:
            return
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return
        days_left = (expiry - datetime.datetime.utcnow()).days
        if days_left < 0:
            self.add("PA050", "high", "TLS certificate has expired",
                     "The site's TLS certificate expired %d day(s) ago."
                     % abs(days_left),
                     evidence="notAfter %s" % not_after,
                     remediation="Renew the TLS certificate immediately.")
        elif days_left <= 30:
            self.add("PA050", "medium", "TLS certificate expires soon",
                     "The site's TLS certificate expires in %d day(s)."
                     % days_left,
                     evidence="notAfter %s" % not_after,
                     remediation="Renew the TLS certificate before it expires.")

    def check_server_disclosure(self, home):
        """Server and PHP version disclosure in response headers."""
        headers = home.headers if home is not None else {}
        server = headers.get("server", "")
        if re.search(r"/\d", server):
            self.add("PA051", "low", "Server header discloses software version",
                     "The Server header reveals the exact server version, "
                     "which helps an attacker pick matching exploits.",
                     evidence="Server: %s" % server,
                     remediation="Strip version details from the Server "
                     "header (e.g. ServerTokens Prod on Apache).")
        powered = headers.get("x-powered-by", "")
        if re.search(r"PHP/\d", powered, re.I):
            self.add("PA051", "low", "X-Powered-By header discloses PHP version",
                     "The X-Powered-By header reveals the PHP version.",
                     evidence="X-Powered-By: %s" % powered,
                     remediation="Disable expose_php in php.ini, or strip "
                     "the header at the web server.")

    def check_wpscan_live(self):
        """Live WPScan lookups for core/plugins/themes (needs an API key)."""
        if not self.wpscan_api_key:
            return
        self.wpscan_used = True

        def severity_for(title):
            low = title.lower()
            if any(word in low for word in (
                    "arbitrary file upload", "remote code execution",
                    "sql injection", "authentication bypass",
                    "privilege escalation")):
                return "high"
            return "medium"

        if self.core_version:
            for vuln in wpscan.lookup("core", None, self.core_version,
                                      self.wpscan_api_key, self.timeout):
                self.add("PA060", severity_for(vuln["title"]),
                         "WPScan: %s" % vuln["title"],
                         "WordPress core %s is affected (fixed in %s)."
                         % (self.core_version, vuln["fixed_in"]),
                         evidence="WPScan live lookup",
                         remediation="Update WordPress core to %s or later."
                         % vuln["fixed_in"],
                         refs=vuln["references"])
        for slug, version in sorted(self.plugins.items()):
            if not version:
                continue
            for vuln in wpscan.lookup("plugins", slug, version,
                                      self.wpscan_api_key, self.timeout):
                self.add("PA060", severity_for(vuln["title"]),
                         "WPScan: %s (%s)" % (vuln["title"], slug),
                         "%s %s is affected (fixed in %s)."
                         % (slug, version, vuln["fixed_in"]),
                         evidence="WPScan live lookup",
                         remediation="Update %s to %s or later."
                         % (slug, vuln["fixed_in"]),
                         refs=vuln["references"])
        for slug, version in sorted(self.themes.items()):
            if not version:
                continue
            for vuln in wpscan.lookup("themes", slug, version,
                                      self.wpscan_api_key, self.timeout):
                self.add("PA060", severity_for(vuln["title"]),
                         "WPScan: %s (%s)" % (vuln["title"], slug),
                         "%s %s is affected (fixed in %s)."
                         % (slug, version, vuln["fixed_in"]),
                         evidence="WPScan live lookup",
                         remediation="Update %s to %s or later."
                         % (slug, vuln["fixed_in"]),
                         refs=vuln["references"])

    def check_transport_headers(self, home):
        """HTTPS and security headers on the homepage response."""
        if self.base_url.startswith("http://"):
            self.add("PA040", "medium", "Site is served over plain HTTP",
                     "Traffic (including logins) is not encrypted.",
                     evidence=self.base_url,
                     remediation="Serve the site over HTTPS with a valid "
                     "certificate and redirect HTTP to HTTPS.")
        headers = home.headers if home is not None else {}
        for name, (expected, severity, title) in SECURITY_HEADERS.items():
            value = headers.get(name)
            if value is None:
                self.add("PA041", severity, title,
                         "Response header %s is missing." % name,
                         remediation="Set the header in the web server or "
                         "via a security plugin.")
            elif expected and expected.lower() not in value.lower():
                self.add("PA041", severity, title,
                         "Response header %s has an unexpected value: %s"
                         % (name, value),
                         remediation="Set %s to '%s'." % (name, expected))
        if self.base_url.startswith("https://") and "strict-transport-security" not in headers:
            self.add("PA042", "low", "Missing Strict-Transport-Security header",
                     "HSTS is not set, so browsers are not forced to use HTTPS.",
                     remediation="Send Strict-Transport-Security with a "
                     "long max-age once HTTPS is fully working.")

    def run(self):
        """Run all checks and return the findings list."""
        home = None
        try:
            home = self.check_homepage()
        except ScanError as exc:
            raise ScanError("homepage check failed: %s" % exc)
        if self.is_wordpress:
            try:
                self.check_rest_api()
            except ScanError:
                pass
            try:
                self.check_plugins_themes()
            except ScanError:
                pass
            try:
                self.check_exposures()
            except ScanError:
                pass
            try:
                self.check_install_and_repo()
            except ScanError:
                pass
            try:
                self.check_wpscan_live()
            except ScanError:
                pass
        try:
            self.check_transport_headers(home)
        except ScanError:
            pass
        try:
            self.check_server_disclosure(home)
        except ScanError:
            pass
        self.check_tls()
        return self.findings


def scan_url(base_url, timeout=10, max_requests=250, cookie=None,
             wpscan_api_key=None, delay=None, workers=10, mode="fast"):
    """Scan one URL and return (findings, scanner)."""
    kwargs = {}
    if delay is not None:
        kwargs["delay"] = delay
    scanner = Scanner(base_url, timeout=timeout, max_requests=max_requests,
                      cookie=cookie, wpscan_api_key=wpscan_api_key,
                      workers=workers, mode=mode, **kwargs)
    findings = scanner.run()
    return findings, scanner
