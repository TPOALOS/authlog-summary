#!/usr/bin/env python3
"""authlog-summary - summarize SSH authentication logs (defensive, read-only).

Parses sshd lines from syslog-style auth logs and reports failed logins per
source IP, most-targeted usernames, failures by hour, and IPs that logged in
successfully after failing (worth investigating). With --suggest it prints
candidate IPs for your own blocklist; it never blocks anything itself.
Standard library only. Exit code 0 = nothing over threshold, 1 = suspicious IPs, 2 = error.
"""
import argparse
import collections
import ipaddress
import json
import re
import sys

__version__ = "1.1.0"

TS = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+(\d{2}):\d{2}:\d{2}\s")
TS_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ](\d{2}):\d{2}:\d{2}")  # rsyslog high-precision / journalctl -o short-iso
FAILED = re.compile(r"sshd\[\d+\]: Failed (?:password|publickey|keyboard-interactive/pam) "
                    r"for (?:invalid user )?(\S+) from (\S+) port \d+")
INVALID = re.compile(r"sshd\[\d+\]: Invalid user (\S*) from (\S+)")
ACCEPTED = re.compile(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port \d+")
PREAUTH = re.compile(r"sshd\[\d+\]: (?:Connection closed by|Disconnected from) (?:authenticating user|invalid user) "
                     r"(\S+) (\S+) port \d+ \[preauth\]")


def parse_ignores(items):
    """CIDR/IP strings -> networks. Raises ValueError on a bad entry."""
    return [ipaddress.ip_network(i, strict=False) for i in items]


def is_ignored(ip, nets):
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def subnet_of(ip):
    """/24 for IPv4, /64 for IPv6; the input itself when it is not an IP address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network("%s/%d" % (addr, 24 if addr.version == 4 else 64), strict=False))


def hour_of(line):
    m = TS.match(line) or TS_ISO.match(line)
    return int(m.group(1)) if m else None


def analyze(lines, ignore=()):
    """Return a stats dict from an iterable of log lines (``ignore``: networks to leave out)."""
    fails = collections.Counter()
    users_by_ip = collections.defaultdict(set)
    user_targets = collections.Counter()
    by_hour = collections.Counter()
    first_fail_seen = set()
    success_after_fail = {}
    successes = 0
    root_logins, password_logins, preauth = [], 0, collections.Counter()
    for line in lines:
        m = FAILED.search(line)
        if m:
            user, ip = m.groups()
            if is_ignored(ip, ignore):
                continue
            fails[ip] += 1
            users_by_ip[ip].add(user)
            user_targets[user] += 1
            first_fail_seen.add(ip)
            hour = hour_of(line)
            if hour is not None:
                by_hour[hour] += 1
            continue
        m = ACCEPTED.search(line)
        if m:
            method, user, ip = m.groups()
            if is_ignored(ip, ignore):
                continue
            successes += 1
            if method == "password":
                password_logins += 1
            if user == "root":
                root_logins.append(ip)
            if ip in first_fail_seen:
                success_after_fail[ip] = user
            continue
        # "Invalid user" lines duplicate Failed lines; only used to count users seen.
        m = INVALID.search(line)
        if m and m.group(1):
            if not is_ignored(m.group(2), ignore):
                users_by_ip[m.group(2)].add(m.group(1))
            continue
        m = PREAUTH.search(line)
        if m and not is_ignored(m.group(2), ignore):
            preauth[m.group(2)] += 1
    return {"fails": fails, "users_by_ip": users_by_ip, "user_targets": user_targets,
            "by_hour": by_hour, "success_after_fail": success_after_fail,
            "successes": successes, "root_logins": root_logins, "password_logins": password_logins,
            "preauth_drops": preauth}


def suspicious(stats, threshold):
    """IPs with >= threshold failures, most active first."""
    return [(ip, n) for ip, n in stats["fails"].most_common() if n >= threshold]


def by_subnet(stats):
    """Failures grouped by /24 (IPv4) or /64 (IPv6), with the number of distinct addresses."""
    groups = collections.defaultdict(lambda: [0, set()])
    for ip, n in stats["fails"].items():
        g = groups[subnet_of(ip)]
        g[0] += n
        g[1].add(ip)
    return sorted(((net, n, len(ips)) for net, (n, ips) in groups.items()), key=lambda r: (-r[1], r[0]))


def to_json(stats, threshold, subnets=False):
    data = {
        "failed_logins": sum(stats["fails"].values()),
        "successful_logins": stats["successes"],
        "threshold": threshold,
        "ips": [{"ip": ip, "failures": n, "usernames_tried": len(stats["users_by_ip"][ip]),
                 "over_threshold": n >= threshold} for ip, n in stats["fails"].most_common()],
        "usernames": [{"user": u, "failures": n} for u, n in stats["user_targets"].most_common()],
        "failures_by_hour": {"%02d" % h: n for h, n in sorted(stats["by_hour"].items())},
        "success_after_fail": [{"ip": ip, "user": u} for ip, u in sorted(stats["success_after_fail"].items())],
        "root_logins": sorted(set(stats["root_logins"])),
        "password_logins": stats["password_logins"],
        "preauth_drops": dict(stats["preauth_drops"].most_common()),
    }
    if subnets:
        data["subnets"] = [{"subnet": net, "failures": n, "addresses": k} for net, n, k in by_subnet(stats)]
    return data


def render(stats, threshold, top=10, subnets=False):
    out = ["Failed logins: %d from %d IP(s); successful logins: %d" % (
        sum(stats["fails"].values()), len(stats["fails"]), stats["successes"])]
    out.append("\nTop source IPs (failures, distinct usernames tried):")
    for ip, n in stats["fails"].most_common(top):
        flag = "  <-- over threshold" if n >= threshold else ""
        out.append("  %-40s %5d %4d%s" % (ip, n, len(stats["users_by_ip"][ip]), flag))
    out.append("\nMost targeted usernames:")
    for user, n in stats["user_targets"].most_common(top):
        out.append("  %-20s %5d" % (user, n))
    if stats["by_hour"]:
        out.append("\nFailures by hour:")
        peak = max(stats["by_hour"].values())
        for h in sorted(stats["by_hour"]):
            bar = "#" * max(1, round(30 * stats["by_hour"][h] / peak))
            out.append("  %02d %-30s %d" % (h, bar, stats["by_hour"][h]))
    if subnets:
        out.append("\nFailures by subnet (/24 IPv4, /64 IPv6):")
        for net, n, k in by_subnet(stats)[:top]:
            out.append("  %-40s %5d %4d address(es)" % (net, n, k))
    if stats["root_logins"]:
        out.append("\nSuccessful root logins (investigate):")
        for ip in sorted(set(stats["root_logins"])):
            out.append("  from %s" % ip)
    if stats["password_logins"]:
        out.append("\nSuccessful password (not key) logins: %d" % stats["password_logins"])
    if stats["success_after_fail"]:
        out.append("\nSuccessful login from an IP that previously failed (investigate):")
        for ip, user in sorted(stats["success_after_fail"].items()):
            out.append("  %s as %s" % (ip, user))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize SSH auth logs (read-only).")
    ap.add_argument("logfile", help="auth log path, or - for stdin")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failures per IP to flag (default 5)")
    ap.add_argument("--suggest", action="store_true",
                    help="print flagged IPs one per line for your blocklist review")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--by-subnet", action="store_true",
                    help="also group failures by /24 (IPv4) or /64 (IPv6) to expose distributed attacks")
    ap.add_argument("--ignore", action="append", default=[], metavar="IP_OR_CIDR",
                    help="leave this address or network out (your own hosts, monitoring); repeatable")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        ignore = parse_ignores(args.ignore)
    except ValueError as exc:
        print("authlog-summary: bad --ignore value: %s" % exc, file=sys.stderr)
        return 2
    try:
        if args.logfile == "-":
            stats = analyze(sys.stdin, ignore)
        else:
            with open(args.logfile, errors="replace") as fh:
                stats = analyze(fh, ignore)
    except OSError as exc:
        print("authlog-summary: %s" % exc, file=sys.stderr)
        return 2
    flagged = suspicious(stats, args.threshold)
    if args.json:
        data = to_json(stats, args.threshold, args.by_subnet)
        if args.suggest:
            data["suggested_blocklist_candidates"] = [ip for ip, _ in flagged]
        print(json.dumps(data, indent=2))
        return 1 if flagged else 0
    print(render(stats, args.threshold, subnets=args.by_subnet))
    if args.suggest and flagged:
        print("\nCandidate IPs for blocklist (review before use):")
        for ip, _ in flagged:
            print(ip)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
