import ipaddress
from pathlib import Path

from authwatch import detect, exclude_ips, parse_lines
from authwatch.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"
YEAR = 2026


def load_sample():
    with open(SAMPLE, encoding="utf-8") as handle:
        return list(parse_lines(handle, YEAR))


def nets(*values):
    return [ipaddress.ip_network(v, strict=False) for v in values]


def test_exclude_single_ip_and_cidr():
    events = load_sample()
    assert {e.ip for e in exclude_ips(events, nets("203.0.113.45"))}.isdisjoint({"203.0.113.45"})
    remaining = exclude_ips(events, nets("198.51.100.0/24"))
    assert not any(e.ip.startswith("198.51.100.") for e in remaining)
    assert any(e.ip.startswith("203.0.113.") for e in remaining)


def test_no_networks_keeps_everything():
    events = load_sample()
    assert exclude_ips(events, []) == events


def test_ipv4_network_does_not_match_ipv6_address():
    from authwatch import parse_line

    line = "Nov  8 10:00:00 h sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    event = parse_line(line, YEAR)
    assert exclude_ips([event], nets("0.0.0.0/0")) == [event]


def test_ignored_attacker_produces_no_alert():
    kept = exclude_ips(load_sample(), nets("203.0.113.45"))
    assert [a.ip for a in detect(kept)] == ["198.51.100.23", "198.51.100.99"]


def test_cli_ignore_ip_option(capsys):
    assert main([str(SAMPLE), "--year", "2026", "--ignore-ip", "203.0.113.0/24", "--json"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.45" not in out and "198.51.100.23" in out


def test_cli_ips_only_prints_one_ip_per_line(capsys):
    assert main([str(SAMPLE), "--year", "2026", "--ips-only"]) == 0
    assert capsys.readouterr().out.split() == ["203.0.113.45", "198.51.100.23", "198.51.100.99"]


def test_cli_rejects_bad_ignore_value(capsys):
    assert main([str(SAMPLE), "--ignore-ip", "not-an-ip"]) == 2
    assert "invalid --ignore-ip" in capsys.readouterr().err
