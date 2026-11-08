import json
from datetime import datetime
from pathlib import Path

import pytest

from authwatch import detect, parse_line, parse_lines, summarize
from authwatch.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"
YEAR = 2026


def failed(ts, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    return f"{ts} host sshd[1]: Failed password for {prefix}{user} from {ip} port 22 ssh2"


def test_parse_failed_and_invalid_user():
    event = parse_line(failed("Nov  8 03:12:03", "admin", "203.0.113.45", invalid=True), YEAR)
    assert event.kind == "failed"
    assert event.invalid_user is True
    assert event.user == "admin" and event.ip == "203.0.113.45"
    assert event.time == datetime(2026, 11, 8, 3, 12, 3)


def test_parse_accepted_and_ipv6():
    line = "Nov 18 10:00:00 host sshd[9]: Accepted publickey for deploy from 2001:db8::1 port 22 ssh2"
    event = parse_line(line, YEAR)
    assert event.kind == "accepted" and event.ip == "2001:db8::1"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "Nov  8 03:11:40 web01 CRON[1]: pam_unix(cron:session): session opened",
        "Nov  8 03:11:40 web01 sshd[1]: Connection closed by 203.0.113.9 port 22",
        "Feb 30 03:11:40 web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
    ],
)
def test_unrelated_or_invalid_lines_are_ignored(line):
    assert parse_line(line, YEAR) is None


def make_events(count, ip="203.0.113.5", gap=10, user="root"):
    lines = [
        failed(f"Nov  8 10:00:{i * gap:02d}" if i * gap < 60 else f"Nov  8 10:01:{i * gap - 60:02d}", user, ip)
        for i in range(count)
    ]
    return list(parse_lines(lines, YEAR))


def test_brute_force_detected_at_threshold():
    alerts = detect(make_events(5), threshold=5, window=300)
    assert len(alerts) == 1
    assert alerts[0].kind == "brute_force" and alerts[0].severity == "high"
    assert alerts[0].failures == 5


def test_below_threshold_is_quiet():
    assert detect(make_events(4), threshold=5, window=300) == []


def test_slow_failures_outside_window_do_not_trigger():
    lines = [failed(f"Nov  8 {h:02d}:00:00", "root", "203.0.113.5") for h in range(6)]
    assert detect(list(parse_lines(lines, YEAR)), threshold=5, window=300) == []


def test_success_after_failures_is_critical():
    events = make_events(6)
    accepted = parse_line("Nov  8 10:02:00 host sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2", YEAR)
    alerts = detect(events + [accepted])
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].kind == "success_after_failures"


def test_username_spray_medium():
    lines = [failed(f"Nov  8 {9 + i:02d}:00:00", f"user{i}", "198.51.100.9", invalid=True) for i in range(5)]
    alerts = detect(list(parse_lines(lines, YEAR)), threshold=5, window=300, spray_users=5)
    assert len(alerts) == 1 and alerts[0].kind == "username_spray" and alerts[0].severity == "medium"


def test_ips_are_tracked_separately():
    events = make_events(5, ip="203.0.113.1") + make_events(4, ip="203.0.113.2")
    alerts = detect(events)
    assert [a.ip for a in alerts] == ["203.0.113.1"]


def test_invalid_settings_rejected():
    with pytest.raises(ValueError):
        detect([], threshold=0)


def test_sample_log_end_to_end():
    with open(SAMPLE, encoding="utf-8") as handle:
        events = list(parse_lines(handle, YEAR))
    alerts = detect(events)
    assert [(a.ip, a.severity) for a in alerts] == [
        ("203.0.113.45", "critical"),
        ("198.51.100.23", "high"),
        ("198.51.100.99", "medium"),
    ]
    summary = summarize(events)
    assert summary["failed"] == 22 and summary["accepted"] == 3


def test_cli_text_and_exit_codes(capsys):
    assert main([str(SAMPLE), "--year", "2026"]) == 0
    out = capsys.readouterr().out
    assert "[CRITICAL] success_after_failures from 203.0.113.45" in out
    assert main([str(SAMPLE), "--year", "2026", "--fail-on-alert"]) == 1


def test_cli_json(capsys):
    assert main([str(SAMPLE), "--year", "2026", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["alerts"]) == 3 and data["alerts"][0]["severity"] == "critical"


def test_cli_missing_file_and_bad_option(capsys):
    assert main(["/no/such/file.log"]) == 2
    assert main([str(SAMPLE), "--threshold", "0"]) == 2
