"""Command line interface for PressAudit."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import format_html, format_json, format_text
from .scanner import ScanError, scan_url
from .updatedb import update_db


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pressaudit",
        description="Detection-only WordPress security scanner. "
                    "Only scan sites you own or have permission to test.")
    parser.add_argument("--version", action="version",
                        version="pressaudit %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan one WordPress site")
    scan.add_argument("url", help="Site URL, e.g. https://example.com")
    scan.add_argument("--json", dest="json_out", default=None,
                      help="Write the JSON report to this file")
    scan.add_argument("--html", dest="html_out", default=None,
                      help="Write an HTML report to this file")
    scan.add_argument("--timeout", type=float, default=10,
                      help="Per-request timeout in seconds (default 10)")
    scan.add_argument("--max-requests", type=int, default=250,
                      help="Maximum HTTP requests per target (default 250)")
    scan.add_argument("--cookie", default=None,
                      help="Cookie header to send (for scanning your own "
                      "logged-in site), e.g. 'wordpress_logged_in_x=abc'")
    scan.add_argument("--wpscan-api-key", default=None,
                      help="WPScan API token for live vulnerability lookups "
                      "(free at https://wpscan.com/api)")
    scan.add_argument("--workers", type=int, default=10,
                      help="Parallel requests for plugin/theme probing "
                      "(default 10; use 1 for strictly sequential scans)")
    scan.add_argument("--mode", choices=["fast", "deep"], default="fast",
                      help="fast: popular + high-risk plugins/themes; "
                      "deep: ~120 plugins and ~40 themes (slower)")
    scan.add_argument("--quiet", action="store_true",
                      help="Only print the summary line")
    multi = sub.add_parser("scan-list", help="Scan URLs listed in a file")
    multi.add_argument("file", help="Text file with one URL per line")
    multi.add_argument("--json", dest="json_out", default=None,
                       help="Write the combined JSON report to this file")
    multi.add_argument("--timeout", type=float, default=10)
    multi.add_argument("--max-requests", type=int, default=250)
    multi.add_argument("--cookie", default=None)
    multi.add_argument("--wpscan-api-key", default=None)
    multi.add_argument("--workers", type=int, default=10)
    multi.add_argument("--mode", choices=["fast", "deep"], default="fast")
    upd = sub.add_parser(
        "update-db",
        help="Build a larger local vulnerability database from the WPScan API")
    upd.add_argument("--wpscan-api-key", required=True,
                     help="WPScan API token (free at https://wpscan.com/api)")
    upd.add_argument("--out", default=None,
                     help="Output path (default ~/.pressaudit/vulndb.json)")
    upd.add_argument("--timeout", type=float, default=10)
    return parser


def _exit_code(findings):
    severities = {f.severity for f in findings}
    if "high" in severities or "medium" in severities:
        return 1
    return 0


def _run_scan(url, args):
    try:
        findings, scanner = scan_url(
            url, timeout=args.timeout, max_requests=args.max_requests,
            cookie=getattr(args, "cookie", None),
            wpscan_api_key=getattr(args, "wpscan_api_key", None),
            workers=getattr(args, "workers", 10),
            mode=getattr(args, "mode", "fast"))
    except ScanError as exc:
        print("pressaudit: error scanning %s: %s" % (url, exc), file=sys.stderr)
        return None, None, 2
    return findings, scanner, _exit_code(findings)


def _run_update_db(args):
    def progress(kind, slug, ok):
        label = "core" if kind == "core" else "%s/%s" % (kind, slug)
        print("  %s %s" % ("ok  " if ok else "fail", label))

    try:
        fetched, total, path = update_db(
            args.wpscan_api_key, out_path=args.out,
            timeout=args.timeout, progress=progress)
    except ValueError as exc:
        print("pressaudit: %s" % exc, file=sys.stderr)
        return 2
    print("pressaudit: fetched %d components, database now holds %d "
          "entries: %s" % (fetched, total, path))
    print("Note: the free WPScan tier allows 25 API requests per day, so a "
          "full refresh may take several days. Re-run to continue.")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "update-db":
        return _run_update_db(args)
    if args.command == "scan":
        findings, scanner, code = _run_scan(args.url, args)
        if findings is None:
            return code
        if args.quiet:
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            print("%s: %s" % (args.url, counts or "no findings"))
        else:
            print(format_text(args.url, findings, scanner.core_version))
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as handle:
                handle.write(format_json(args.url, findings, scanner))
        if args.html_out:
            with open(args.html_out, "w", encoding="utf-8") as handle:
                handle.write(format_html(args.url, findings, scanner))
        return code
    if args.command == "scan-list":
        try:
            with open(args.file, encoding="utf-8") as handle:
                urls = [line.strip() for line in handle
                        if line.strip() and not line.strip().startswith("#")]
        except OSError as exc:
            print("pressaudit: cannot read %s: %s" % (args.file, exc),
                  file=sys.stderr)
            return 2
        combined = []
        worst = 0
        for url in urls:
            findings, scanner, code = _run_scan(url, args)
            if findings is None:
                worst = max(worst, 2)
                continue
            worst = max(worst, code)
            combined.append({
                "target": url,
                "findings": [f.to_dict() for f in findings],
            })
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            print("%s: %s" % (url, counts or "no findings"))
        if args.json_out:
            import json
            with open(args.json_out, "w", encoding="utf-8") as handle:
                json.dump(combined, handle, indent=2)
        return worst
    return 2


if __name__ == "__main__":
    sys.exit(main())
