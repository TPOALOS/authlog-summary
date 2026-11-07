import contextlib
import io
import json
import os
import tempfile
import unittest

import authlog_summary as als

# Documentation-only IP ranges (RFC 5737 / RFC 3849) and made-up users.
BAD = "203.0.113.7"
OK = "198.51.100.20"
V6 = "2001:db8::1"


def fail(ip, user="root", hour="03", invalid=False):
    iu = "invalid user " if invalid else ""
    return "Nov  7 %s:12:01 host sshd[101]: Failed password for %s%s from %s port 5000 ssh2" % (
        hour, iu, user, ip)


def accept(ip, user="alice"):
    return "Nov  7 09:00:00 host sshd[102]: Accepted publickey for %s from %s port 6000 ssh2" % (
        user, ip)


class AnalyzeTests(unittest.TestCase):
    def test_counts(self):
        lines = [fail(BAD)] * 6 + [fail(OK, "bob")] + [accept(OK, "bob")]
        s = als.analyze(lines)
        self.assertEqual(s["fails"][BAD], 6)
        self.assertEqual(s["fails"][OK], 1)
        self.assertEqual(s["successes"], 1)

    def test_invalid_user_and_users_tried(self):
        s = als.analyze([fail(BAD, "admin", invalid=True), fail(BAD, "test", invalid=True)])
        self.assertEqual(s["users_by_ip"][BAD], {"admin", "test"})
        self.assertEqual(s["user_targets"]["admin"], 1)

    def test_ipv6(self):
        s = als.analyze([fail(V6)])
        self.assertEqual(s["fails"][V6], 1)

    def test_hour_histogram(self):
        s = als.analyze([fail(BAD, hour="03"), fail(BAD, hour="03"), fail(BAD, hour="14")])
        self.assertEqual(s["by_hour"][3], 2)
        self.assertEqual(s["by_hour"][14], 1)

    def test_success_after_fail(self):
        s = als.analyze([fail(BAD), accept(BAD, "alice")])
        self.assertEqual(s["success_after_fail"], {BAD: "alice"})
        s2 = als.analyze([accept(BAD, "alice"), fail(BAD)])
        self.assertEqual(s2["success_after_fail"], {})

    def test_threshold(self):
        s = als.analyze([fail(BAD)] * 5 + [fail(OK)] * 2)
        self.assertEqual(als.suspicious(s, 5), [(BAD, 5)])
        self.assertEqual(als.suspicious(s, 6), [])

    def test_garbage_lines_ignored(self):
        s = als.analyze(["", "random text", "sshd: nothing here"])
        self.assertEqual(sum(s["fails"].values()), 0)

    def test_render_mentions_flag(self):
        s = als.analyze([fail(BAD)] * 5)
        self.assertIn("over threshold", als.render(s, 5))


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "auth.log")
            with open(p, "w") as fh:
                fh.write("\n".join([fail(OK)]) + "\n")
            self.assertEqual(als.main([p]), 0)
            with open(p, "w") as fh:
                fh.write("\n".join([fail(BAD)] * 6) + "\n")
            self.assertEqual(als.main([p, "--suggest"]), 1)
        self.assertEqual(als.main(["/nonexistent/auth.log"]), 2)


def iso_fail(ip, user="root", hour="03", style="T"):
    return "2026-11-07%s%s:12:01.123456+03:00 host sshd[101]: Failed password for %s from %s port 5000 ssh2" % (
        style, hour, user, ip)


def accept_with(method, ip, user):
    return "Nov  7 09:00:00 host sshd[102]: Accepted %s for %s from %s port 6000 ssh2" % (method, user, ip)


def preauth(ip, user="admin", kind="Connection closed by invalid user"):
    return "Nov  7 09:00:00 host sshd[103]: %s %s %s port 7000 [preauth]" % (kind, user, ip)


def run_main(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = als.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TimestampTests(unittest.TestCase):
    def test_iso_timestamps_give_hours(self):
        s = als.analyze([iso_fail(BAD, hour="03"), iso_fail(BAD, hour="14", style=" ")])
        self.assertEqual(dict(s["by_hour"]), {3: 1, 14: 1})

    def test_classic_syslog_still_works(self):
        self.assertEqual(dict(als.analyze([fail(BAD, hour="07")])["by_hour"]), {7: 1})

    def test_line_without_timestamp_counts_but_has_no_hour(self):
        s = als.analyze(["host sshd[1]: Failed password for root from %s port 1 ssh2" % BAD])
        self.assertEqual((s["fails"][BAD], dict(s["by_hour"])), (1, {}))


class NewSignalTests(unittest.TestCase):
    def test_root_login_and_password_login(self):
        s = als.analyze([accept_with("password", OK, "root"), accept_with("publickey", OK, "alice")])
        self.assertEqual(s["root_logins"], [OK])
        self.assertEqual((s["password_logins"], s["successes"]), (1, 2))

    def test_preauth_drops(self):
        s = als.analyze([preauth(BAD), preauth(BAD, kind="Disconnected from invalid user"),
                         preauth(OK, kind="Connection closed by authenticating user")])
        self.assertEqual(dict(s["preauth_drops"]), {BAD: 2, OK: 1})

    def test_preauth_does_not_count_as_failed_login(self):
        self.assertEqual(sum(als.analyze([preauth(BAD)])["fails"].values()), 0)

    def test_render_mentions_root_logins(self):
        text = als.render(als.analyze([accept_with("password", OK, "root")]), 5)
        self.assertIn("root logins", text)
        self.assertIn("password (not key) logins: 1", text)


class IgnoreTests(unittest.TestCase):
    def test_parse(self):
        nets = als.parse_ignores(["203.0.113.7", "198.51.100.0/24", "2001:db8::/32"])
        self.assertEqual(len(nets), 3)
        with self.assertRaises(ValueError):
            als.parse_ignores(["not-an-ip"])

    def test_is_ignored(self):
        nets = als.parse_ignores(["198.51.100.0/24", "2001:db8::/32"])
        self.assertTrue(als.is_ignored("198.51.100.99", nets))
        self.assertTrue(als.is_ignored("2001:db8::5", nets))
        self.assertFalse(als.is_ignored("203.0.113.7", nets))
        self.assertFalse(als.is_ignored("garbage", nets))
        self.assertFalse(als.is_ignored(BAD, []))

    def test_ignored_hosts_excluded_everywhere(self):
        nets = als.parse_ignores([OK])
        s = als.analyze([fail(OK)] * 9 + [accept_with("password", OK, "root"), preauth(OK)] + [fail(BAD)], nets)
        self.assertEqual(set(s["fails"]), {BAD})
        self.assertEqual((s["successes"], s["root_logins"], dict(s["preauth_drops"])), (0, [], {}))

    def test_cli_ignore_changes_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "auth.log")
            with open(p, "w") as fh:
                fh.write("\n".join([fail(BAD)] * 6))
            self.assertEqual(run_main(p)[0], 1)
            self.assertEqual(run_main(p, "--ignore", "203.0.113.0/24")[0], 0)
            code, _, err = run_main(p, "--ignore", "nope")
            self.assertEqual(code, 2)
            self.assertIn("--ignore", err)


class SubnetTests(unittest.TestCase):
    def test_subnet_of(self):
        self.assertEqual(als.subnet_of("203.0.113.77"), "203.0.113.0/24")
        self.assertEqual(als.subnet_of("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64")
        self.assertEqual(als.subnet_of("weird-host"), "weird-host")

    def test_distributed_attack_visible_by_subnet(self):
        lines = []
        for last in range(1, 7):
            lines += [fail("203.0.113.%d" % last)] * 2  # no single IP reaches the threshold
        s = als.analyze(lines)
        self.assertEqual(als.suspicious(s, 5), [])
        self.assertEqual(als.by_subnet(s), [("203.0.113.0/24", 12, 6)])
        self.assertIn("203.0.113.0/24", als.render(s, 5, subnets=True))
        self.assertNotIn("Failures by subnet", als.render(s, 5))


class JsonTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._t.name, "auth.log")
        lines = [fail(BAD)] * 6 + [accept_with("password", BAD, "root"), accept_with("publickey", OK, "alice")]
        with open(self.path, "w") as fh:
            fh.write("\n".join(lines))

    def tearDown(self):
        self._t.cleanup()

    def test_json_structure(self):
        code, out, _ = run_main(self.path, "--json", "--suggest", "--by-subnet")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["failed_logins"], 6)
        self.assertEqual(data["ips"][0], {"ip": BAD, "failures": 6, "usernames_tried": 1, "over_threshold": True})
        self.assertEqual(data["root_logins"], [BAD])
        self.assertEqual(data["success_after_fail"], [{"ip": BAD, "user": "root"}])
        self.assertEqual(data["suggested_blocklist_candidates"], [BAD])
        self.assertEqual(data["subnets"][0]["subnet"], "203.0.113.0/24")
        self.assertEqual(data["failures_by_hour"], {"03": 6})

    def test_json_without_optional_sections(self):
        _, out, _ = run_main(self.path, "--json")
        data = json.loads(out)
        self.assertNotIn("subnets", data)
        self.assertNotIn("suggested_blocklist_candidates", data)

    def test_json_exit_codes_match_text(self):
        self.assertEqual(run_main(self.path, "--json", "-t", "100")[0], 0)

    def test_missing_file(self):
        self.assertEqual(run_main(os.path.join(self._t.name, "nope"))[0], 2)


if __name__ == "__main__":
    unittest.main()
