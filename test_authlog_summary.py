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


if __name__ == "__main__":
    unittest.main()
