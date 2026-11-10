"""Detection rules: brute force, success after failures, and username spraying."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Sequence, Tuple, Union

from .parser import Event

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


@dataclass
class Alert:
    """A suspicious source IP and why it was flagged."""

    severity: str  # critical, high or medium
    kind: str  # success_after_failures, brute_force or username_spray
    ip: str
    failures: int
    users: List[str]
    first_seen: datetime
    last_seen: datetime
    detail: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "ip": self.ip,
            "failures": self.failures,
            "users": self.users,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "detail": self.detail,
        }


def _densest_window(times: List[datetime], window: int) -> Tuple[int, int, int]:
    """Find the window of `window` seconds holding the most events.

    Returns (count, start_index, end_index) over the sorted `times`.
    """
    best = (0, 0, 0)
    start = 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > window:
            start += 1
        count = end - start + 1
        if count > best[0]:
            best = (count, start, end)
    return best


def detect(
    events: Iterable[Event],
    threshold: int = 5,
    window: int = 300,
    spray_users: int = 5,
) -> List[Alert]:
    """Flag suspicious source IPs.

    Each IP produces at most one alert, using the most serious rule that matches:

    * critical: a login succeeded right after `threshold`+ failures within `window` seconds.
    * high: `threshold`+ failures within `window` seconds.
    * medium: slow username spraying, with `spray_users`+ different usernames tried overall.
    """
    if threshold < 1 or window < 1 or spray_users < 1:
        raise ValueError("threshold, window and spray_users must be positive")

    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    alerts: List[Alert] = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.time)
        failed = [e for e in ip_events if e.kind == "failed"]
        if not failed:
            continue

        count, start, end = _densest_window([e.time for e in failed], window)
        burst = failed[start : end + 1]

        critical = None
        for success in (e for e in ip_events if e.kind == "accepted"):
            before = [f for f in failed if 0 <= (success.time - f.time).total_seconds() <= window]
            if len(before) >= threshold:
                critical = (success, before)
                break

        if critical:
            success, before = critical
            alerts.append(
                Alert(
                    "critical",
                    "success_after_failures",
                    ip,
                    len(before),
                    sorted({f.user for f in before}),
                    before[0].time,
                    success.time,
                    f"Login as '{success.user}' succeeded after {len(before)} failures "
                    f"within {window}s. Treat the account as possibly compromised.",
                )
            )
        elif count >= threshold:
            users = sorted({f.user for f in burst})
            extra = f", targeting {len(users)} different usernames" if len(users) >= spray_users else ""
            alerts.append(
                Alert(
                    "high",
                    "brute_force",
                    ip,
                    count,
                    users,
                    burst[0].time,
                    burst[-1].time,
                    f"{count} failed logins within {window}s{extra}.",
                )
            )
        else:
            users = sorted({f.user for f in failed})
            if len(users) >= spray_users:
                alerts.append(
                    Alert(
                        "medium",
                        "username_spray",
                        ip,
                        len(failed),
                        users,
                        failed[0].time,
                        failed[-1].time,
                        f"{len(failed)} failed logins spread over {len(users)} different "
                        "usernames (slow spray, stays under the burst threshold).",
                    )
                )

    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.failures, a.ip))
    return alerts


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def exclude_ips(events: Iterable[Event], networks: Sequence[Network]) -> List[Event]:
    """Drop events from trusted addresses, such as your office IP or a monitoring host."""
    if not networks:
        return list(events)
    kept: List[Event] = []
    for event in events:
        try:
            address = ipaddress.ip_address(event.ip)
        except ValueError:
            kept.append(event)  # not a parseable address: keep it rather than hide it
            continue
        if not any(net.version == address.version and address in net for net in networks):
            kept.append(event)
    return kept


def summarize(events: Iterable[Event]) -> Dict[str, object]:
    """Overall counts for a set of events."""
    events = list(events)
    failed = [e for e in events if e.kind == "failed"]
    return {
        "events": len(events),
        "failed": len(failed),
        "accepted": len(events) - len(failed),
        "unique_ips": len({e.ip for e in events}),
        "top_users": Counter(e.user for e in failed).most_common(5),
        "top_ips": Counter(e.ip for e in failed).most_common(5),
    }
