# authlog-summary

Summarize SSH authentication logs (syslog-style, e.g. `/var/log/auth.log`).
Read-only and standard library only. It reports; it never blocks anything.

## What it shows

- Failed logins per source IP, with how many distinct usernames each tried
- Most targeted usernames
- Failures by hour of day
- IPs that **logged in successfully after failing** (worth investigating)
- With `--suggest`: IPs over the threshold, one per line, for *your* review before
  adding them to a firewall or fail2ban list

## Usage

```bash
python3 authlog_summary.py /var/log/auth.log
python3 authlog_summary.py /var/log/auth.log --threshold 10 --suggest
zcat /var/log/auth.log.2.gz | python3 authlog_summary.py -
```

Exit codes: `0` nothing over threshold, `1` suspicious IPs found, `2` unreadable file.

Recognized sshd messages: `Failed password|publickey|keyboard-interactive`,
`Invalid user`, and `Accepted ...`. IPv4 and IPv6 sources are supported.

## Tests

Tests use only RFC 5737 / RFC 3849 documentation IPs and made-up usernames:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
