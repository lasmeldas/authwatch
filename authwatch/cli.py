"""Command-line interface for authwatch."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import List, Optional

from . import __version__
from .detector import Alert, detect, summarize
from .parser import parse_lines


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authwatch",
        description="Detect SSH brute-force attacks in an auth log (for servers you own or administer).",
    )
    parser.add_argument("logfile", nargs="?", default="-", help="path to auth.log, or - for stdin (default)")
    parser.add_argument("--threshold", type=int, default=5, help="failures that count as a burst (default 5)")
    parser.add_argument("--window", type=int, default=300, help="burst window in seconds (default 300)")
    parser.add_argument("--spray-users", type=int, default=5, help="distinct usernames that count as a spray (default 5)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog has none; default: current year)")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument("--fail-on-alert", action="store_true", help="exit with status 1 if any alert is found")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _print_text(summary: dict, alerts: List[Alert]) -> None:
    print(
        f"Parsed {summary['events']} login events: {summary['failed']} failed, "
        f"{summary['accepted']} accepted, from {summary['unique_ips']} IP addresses."
    )
    if summary["top_users"]:
        users = ", ".join(f"{name} ({n})" for name, n in summary["top_users"])
        print(f"Most targeted usernames: {users}")
    if not alerts:
        print("\nNo suspicious activity detected.")
        return
    print(f"\n{len(alerts)} alert(s):\n")
    for alert in alerts:
        shown = ", ".join(alert.users[:8]) + (", ..." if len(alert.users) > 8 else "")
        print(f"[{alert.severity.upper()}] {alert.kind} from {alert.ip}")
        print(f"    {alert.detail}")
        print(f"    {alert.first_seen:%b %d %H:%M:%S} -> {alert.last_seen:%b %d %H:%M:%S} | usernames: {shown}")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.logfile == "-":
            events = list(parse_lines(sys.stdin, args.year))
        else:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as handle:
                events = list(parse_lines(handle, args.year))
    except OSError as err:
        print(f"error: cannot read log: {err}", file=sys.stderr)
        return 2

    try:
        alerts = detect(events, args.threshold, args.window, args.spray_users)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    summary = summarize(events)
    if args.json:
        payload = dict(summary)
        payload["alerts"] = [a.to_dict() for a in alerts]
        print(json.dumps(payload, indent=2))
    else:
        _print_text(summary, alerts)

    return 1 if (alerts and args.fail_on_alert) else 0


if __name__ == "__main__":
    raise SystemExit(main())
