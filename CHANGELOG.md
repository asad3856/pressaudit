# Changelog

## 0.4.0 — 9 Nov 2026

- `pressaudit update-db` now uses the WPVulnerability API by default:
  free, no API key, no account, no daily limit (CC0 1.0 public-domain
  data, aggregated from CVE, EUVD, JVN, Patchstack, Wordfence, WPScan).
  Live demo 9 Nov 2026: 74 components fetched, 1,686 new entries added
  (database 8 → 1,694 entries); Contact Form 7 5.3.1 now matches 7
  vulnerabilities, File Manager 6.8 matches 10, core 4.7.1 matches 272.
- Plugin/theme records map exactly (machine-readable `<` / `<=`
  operators). Core records are version-scoped, so the fixed version is
  recovered from source texts ("fixed in 5.8.3", "<= 5.8.2"); entries
  whose bound cannot be recovered are skipped and counted, never guessed
  (441 skipped in the demo run). Unfixed and version-ranged entries are
  skipped the same way.
- WPScan stays as an optional second source: `update-db --source wpscan
  --wpscan-api-key KEY` (free tier 25 requests/day). New module
  `wpvuln.py`; 28 tests pass (was 21).

## 0.3.0 — 8 Nov 2026

- Bigger offline database: `data/vulndb.json` (verified entries, including
  Contact Form 7 CVE-2020-35489 and File Manager CVE-2020-25213), loaded
  from `$PRESSAUDIT_DB`, `~/.pressaudit/vulndb.json`, or the bundled file.
- `pressaudit update-db` builds a much larger local database from the
  WPScan API (free tier: 25 requests/day; progress is saved, re-run to
  continue).
- Parallel enumeration (ThreadPoolExecutor, `--workers`, default 10) and
  fast/deep modes (`--mode deep` probes ~120 plugins and ~40 themes).
- PyPI-ready packaging: verified `python -m build` + `twine check` (see
  docs/PUBLISHING.md; uploading still needs a PyPI account + token).

## 0.2.0 — 8 Nov 2026

- Live vulnerability lookups via the WPScan API (`--wpscan-api-key`, free
  token at https://wpscan.com/api). Without a key the scanner uses only
  its offline database and never contacts WPScan.
- Bigger enumeration: ~40 popular plugins and 16 themes probed, plus
  high-risk plugin list expanded.
- New checks: install page reachable (PA036), exposed `.git`/`.env`
  (PA037), TLS certificate expiry/trust (PA050), Server/PHP version
  disclosure (PA051), live WPScan findings (PA060).
- HTML report (`--html report.html`) alongside the JSON report.
- Authenticated scanning of your own sites via `--cookie`.
- Request budget raised to 150 per target.

## 0.1.0 — 8 Nov 2026

- First release: detection-only WordPress scanner. Core/plugin/theme
  fingerprinting, curated offline vulnerability database, user
  enumeration, XML-RPC, debug.log, wp-config backups, directory listing,
  open registration, HTTPS and security headers, JSON reports, CI exit
  codes.
