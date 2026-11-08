# PressAudit

**Detection-only WordPress security scanner.** Point it at a WordPress site you own (or have permission to test) and it tells you what's exposed and how to fix it — core version and known vulnerabilities, plugin/theme versions, user enumeration, XML-RPC, leaked debug logs and config backups, missing security headers — with a fix for every finding.

Standard library only. No dependencies, no network calls except to the target, no account, no API key needed. Python 3.9+.

> **What it is not:** PressAudit never exploits anything. It does not upload files, does not try logins, does not brute-force passwords, and does not attack other people's sites. Only scan sites you own or have explicit permission to test.

## Why this exists

The well-known WordPress mass-exploitation tools from the 2010s (the most-starred one is a Perl script last updated about 3 years ago) hard-code decade-old plugin exploits, auto-upload web shells, and ship a dorker for mass targeting. They are built for attacking. PressAudit is the opposite job, built the modern way:

- **Detection, not exploitation** — findings + remediation, never payloads.
- **Maintained vulnerability data** — a curated offline database (core + plugins) instead of exploits frozen in 2014–2016, plus optional live WPScan API lookups for the full database, and `pressaudit update-db` to build a large local database from WPScan (free tier: 25 requests/day).
- **Real fingerprinting** — version detection from generator, readme, REST API, and plugin/theme readme files, not just a list of URLs to try. Fast mode probes ~40 popular plugins and 16 themes; deep mode probes ~120 plugins and ~40 themes, concurrently (10 workers by default).
- **Honest reporting** — severity, evidence, and a fix for every finding; JSON and HTML output, and CI exit codes (`0` clean, `1` medium/high findings, `2` scan error).
- **Polite by default** — identifiable User-Agent, 0.15s delay between requests, request budget, per-request timeout.

## Install

```bash
git clone https://github.com/asad3856/pressaudit.git
cd pressaudit
pip install .
```

Or run it without installing:

```bash
PYTHONPATH=src python3 -m pressaudit scan https://example.com
```

## Usage

```bash
# Scan one site
pressaudit scan https://example.com

# Save a JSON report too
pressaudit scan https://example.com --json report.json

# HTML report
pressaudit scan https://example.com --html report.html

# Live WPScan lookups (free token at https://wpscan.com/api)
pressaudit scan https://example.com --wpscan-api-key YOUR_TOKEN

# Build a large local database from WPScan (kept in ~/.pressaudit/vulndb.json)
pressaudit update-db --wpscan-api-key YOUR_TOKEN

# Deep mode: ~120 plugins and ~40 themes, probed concurrently
pressaudit scan https://example.com --mode deep --workers 10

# Scan your own logged-in site with a session cookie
pressaudit scan https://example.com --cookie "wordpress_logged_in_x=abc123"

# Scan a list of your own sites
pressaudit scan-list sites.txt --json reports.json
```

Example output:

```
PressAudit scan: https://example.com
WordPress core: 4.7.1
Findings: high: 3, medium: 2, low: 3, info: 4

[HIGH] WordPress 4.7.0/4.7.1 REST API content injection (PA004)
    Core version 4.7.1 is affected (fixed in 4.7.1).
    Evidence: CVE-2017-5487 affects <= 4.7.1
    Fix: Update WordPress core to 4.7.2 or later. ...
```

## Checks

| ID | Check |
|----|-------|
| PA001 | WordPress detection |
| PA002–PA004 | Core version, end-of-life, known core CVEs |
| PA010 | readme.html version disclosure |
| PA011–PA013 | REST API, user enumeration, author redirect |
| PA020–PA022 | Plugin/theme versions + known plugin vulnerabilities |
| PA030–PA035 | XML-RPC, debug.log, wp-config backups, directory listing, open registration, login page |
| PA036–PA037 | Install page reachable, exposed `.git`/`.env` |
| PA040–PA042 | Plain HTTP, missing security headers, missing HSTS |
| PA050–PA051 | TLS certificate expiry/trust, Server/PHP version disclosure |
| PA060 | Live WPScan findings (only with `--wpscan-api-key`) |

## Limitations

- The offline vulnerability database is a small curated starter set (a few high-confidence core and plugin entries, checked against public CVE records). A missing entry is **not** proof a component is safe — run `pressaudit update-db --wpscan-api-key KEY` to build a much larger local database, or pass `--wpscan-api-key` for live lookups.
- Version detection depends on what the site discloses; a hardened site may hide its version (which is good).
- Single-line, passive checks only: it cannot confirm a vulnerability is exploitable, and it will not find logic flaws or vulnerabilities in custom code.

## License

MIT.
