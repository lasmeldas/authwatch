# authwatch

[![CI](https://github.com/lasmeldas/authwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/lasmeldas/authwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

A small blue-team tool that reads your OpenSSH auth log and tells you who is attacking your server, and whether any attacker got in. It's meant for servers you own or administer.

## Features

- **Brute-force detection:** many failed logins from one IP within a sliding time window.
- **Success-after-failures alerts:** flags the most dangerous case, where a login succeeded right after a burst of failures from the same IP, as *critical*.
- **Slow username-spray detection:** catches attackers who try many usernames slowly enough to stay under the burst threshold.
- **Plain output or JSON**, plus `--fail-on-alert` so it can gate scripts and CI jobs.
- **Zero dependencies**, with tests and CI on Python 3.9, 3.11 and 3.13.

## Install

```bash
git clone https://github.com/lasmeldas/authwatch.git
cd authwatch
pip install -e .
```

## Usage

```bash
authwatch /var/log/auth.log            # Debian/Ubuntu (may need sudo to read)
authwatch /var/log/secure              # RHEL/Fedora
journalctl -u ssh --no-pager | authwatch -   # read from stdin
authwatch auth.log --json              # machine-readable
authwatch auth.log --fail-on-alert     # exit status 1 if anything is flagged
```

Try it on the included sample log:

```console
$ authwatch samples/auth.log --year 2026
Parsed 25 login events: 22 failed, 3 accepted, from 5 IP addresses.
Most targeted usernames: root (7), admin (2), ubuntu (2), guest (2), alice (2)

3 alert(s):

[CRITICAL] success_after_failures from 203.0.113.45
    Login as 'ubuntu' succeeded after 7 failures within 300s. Treat the account as possibly compromised.
    Nov 08 03:12:01 -> Nov 08 03:12:19 | usernames: admin, oracle, root, test, ubuntu
[HIGH] brute_force from 198.51.100.23
    8 failed logins within 300s.
    Nov 08 14:20:01 -> Nov 08 14:20:40 | usernames: admin, guest, postgres, root
[MEDIUM] username_spray from 198.51.100.99
    5 failed logins spread over 5 different usernames (slow spray, stays under the burst threshold).
    Nov 08 09:00:12 -> Nov 08 09:40:02 | usernames: ftpuser, git, guest, jenkins, nagios
```

The sample uses reserved documentation IP addresses (RFC 5737), so nothing in it is real.

## Detection rules

Each IP produces at most one alert, using the most serious rule that matches.

| Severity | Rule | Triggers when |
|----------|------|---------------|
| critical | `success_after_failures` | a login succeeds after `--threshold` or more failures within `--window` seconds |
| high | `brute_force` | `--threshold` or more failures within `--window` seconds |
| medium | `username_spray` | `--spray-users` or more different usernames tried, without a burst |

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `logfile` | `-` (stdin) | path to the log file |
| `--threshold` | 5 | failures that count as a burst |
| `--window` | 300 | burst window in seconds |
| `--spray-users` | 5 | distinct usernames that count as a spray |
| `--year` | current year | syslog timestamps have no year, so set this for older logs |
| `--json` | off | print JSON instead of text |
| `--fail-on-alert` | off | exit with status 1 if any alert is found |

## If you find an attacker

authwatch only reports; it never blocks anything. Common next steps are to disable password logins and use SSH keys only, set `PermitRootLogin no`, run [fail2ban](https://github.com/fail2ban/fail2ban) to ban offenders automatically, and rotate credentials for any account in a *critical* alert.

## Limitations

- Understands OpenSSH `sshd` messages in the classic syslog format only.
- Works per source IP, so a distributed attack from many IPs may stay under the thresholds.
- Treat it as a quick triage tool, not a full intrusion detection system.

## Development

```bash
pip install -e . pytest
pytest -q
```

## License

[MIT](LICENSE)
