# authlog-summary

Summarize SSH authentication logs (syslog-style, e.g. `/var/log/auth.log`).
Read-only and standard library only. It reports; it never blocks anything.

## What it shows

- Failed logins per source IP, with how many distinct usernames each tried
- Most targeted usernames
- Failures by hour of day
- IPs that **logged in successfully after failing** (worth investigating)
- Successful **root** logins and how many logins used a password instead of a key
- Pre-auth drops (`Connection closed by invalid user ... [preauth]`) per IP
- With `--by-subnet`: failures grouped by /24 (IPv4) or /64 (IPv6), which exposes attacks spread over many addresses
- With `--suggest`: IPs over the threshold, one per line, for *your* review before
  adding them to a firewall or fail2ban list

## Usage

```bash
python3 authlog_summary.py /var/log/auth.log
python3 authlog_summary.py /var/log/auth.log --threshold 10 --suggest
zcat /var/log/auth.log.2.gz | python3 authlog_summary.py -
python3 authlog_summary.py /var/log/auth.log --by-subnet --ignore 192.0.2.0/24 --ignore 2001:db8::1
python3 authlog_summary.py /var/log/auth.log --json
journalctl -u ssh -o short-iso | python3 authlog_summary.py -
# or: pip install git+https://github.com/TPOALOS/authlog-summary && authlog-summary /var/log/auth.log
```

`--ignore` leaves your own addresses or networks (monitoring, jump hosts) out of every count.

Exit codes: `0` nothing over threshold, `1` suspicious IPs found, `2` unreadable file.

Recognized sshd messages: `Failed password|publickey|keyboard-interactive`,
`Invalid user`, `Accepted ...` and pre-auth `Connection closed` / `Disconnected` lines. Classic syslog timestamps
and ISO-8601 ones (rsyslog high precision, `journalctl -o short-iso`) are understood. IPv4 and IPv6 sources are supported.

## Tests

Tests use only RFC 5737 / RFC 3849 documentation IPs and made-up usernames:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
