"""Parse OpenSSH (sshd) lines from syslog-style auth logs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f.:]+) port \d+"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f.:]+) port \d+"
)


@dataclass(frozen=True)
class Event:
    """One login attempt: either a failure or a success."""

    time: datetime
    kind: str  # "failed" or "accepted"
    user: str
    ip: str
    method: str
    invalid_user: bool = False


def parse_line(line: str, year: int) -> Optional[Event]:
    """Parse one log line. Returns None for lines that aren't login attempts.

    Syslog timestamps have no year, so the caller supplies one.
    """
    match = _LINE.match(line.rstrip("\n"))
    if not match:
        return None
    try:
        when = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    message = match["msg"]
    failed = _FAILED.match(message)
    if failed:
        return Event(
            when, "failed", failed["user"], failed["ip"], failed["method"], bool(failed["invalid"])
        )
    accepted = _ACCEPTED.match(message)
    if accepted:
        return Event(when, "accepted", accepted["user"], accepted["ip"], accepted["method"])
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Event]:
    """Yield an Event for every login attempt found in `lines`."""
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
