# Changelog

## 1.1.0

- `--json` output
- ISO-8601 timestamps (rsyslog high precision, `journalctl -o short-iso`)
- `--by-subnet` groups failures by /24 or /64 to expose distributed attacks
- `--ignore IP_OR_CIDR` leaves your own hosts out
- Reports successful root logins, password logins and pre-auth drops
- Installable with pip (`authlog-summary` command), CI on Linux and macOS

## 1.0.0

Initial release.
