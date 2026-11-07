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
import re
import sys

__version__ = "1.0.0"

TS = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+(\d{2}):\d{2}:\d{2}\s")
FAILED = re.compile(r"sshd\[\d+\]: Failed (?:password|publickey|keyboard-interactive/pam) "
                    r"for (?:invalid user )?(\S+) from (\S+) port \d+")
INVALID = re.compile(r"sshd\[\d+\]: Invalid user (\S*) from (\S+)")
ACCEPTED = re.compile(r"sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+) port \d+")


def analyze(lines):
    """Return a stats dict from an iterable of log lines."""
    fails = collections.Counter()
    users_by_ip = collections.defaultdict(set)
    user_targets = collections.Counter()
    by_hour = collections.Counter()
    first_fail_seen = set()
    success_after_fail = {}
    successes = 0
    for line in lines:
        m = FAILED.search(line)
        if m:
            user, ip = m.groups()
            fails[ip] += 1
            users_by_ip[ip].add(user)
            user_targets[user] += 1
            first_fail_seen.add(ip)
            t = TS.match(line)
            if t:
                by_hour[int(t.group(1))] += 1
            continue
        m = ACCEPTED.search(line)
        if m:
            user, ip = m.groups()
            successes += 1
            if ip in first_fail_seen:
                success_after_fail[ip] = user
            continue
        # "Invalid user" lines duplicate Failed lines; only used to count users seen.
        m = INVALID.search(line)
        if m and m.group(1):
            users_by_ip[m.group(2)].add(m.group(1))
    return {"fails": fails, "users_by_ip": users_by_ip, "user_targets": user_targets,
            "by_hour": by_hour, "success_after_fail": success_after_fail,
            "successes": successes}


def suspicious(stats, threshold):
    """IPs with >= threshold failures, most active first."""
    return [(ip, n) for ip, n in stats["fails"].most_common() if n >= threshold]


def render(stats, threshold, top=10):
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
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        if args.logfile == "-":
            stats = analyze(sys.stdin)
        else:
            with open(args.logfile, errors="replace") as fh:
                stats = analyze(fh)
    except OSError as exc:
        print("authlog-summary: %s" % exc, file=sys.stderr)
        return 2
    flagged = suspicious(stats, args.threshold)
    print(render(stats, args.threshold))
    if args.suggest and flagged:
        print("\nCandidate IPs for blocklist (review before use):")
        for ip, _ in flagged:
            print(ip)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
