import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from burp_ffuf_copy import build_command, default_options, parse_request  # noqa: E402

RAW_GET = ("GET /FUZZ HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n"
           "User-Agent: Mozilla/5.0\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n")
RAW_POST = ("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 30\r\n"
            "Content-Type: application/json\r\n\r\n{\"user\":\"FUZZ\",\"p\":\"$x\"}")


def opts(**changes):
    o = default_options()
    for k, v in changes.items():
        o[k] = list(v)
    return o


class ParseTests(unittest.TestCase):
    def test_skips_ffuf_headers_keeps_duplicates(self):
        method, headers, body = parse_request(RAW_GET)
        self.assertEqual(method, "GET")
        self.assertEqual(headers, [("User-Agent", "Mozilla/5.0"), ("Cookie", "a=1"), ("Cookie", "b=2")])
        self.assertEqual(body, "")

    def test_keeps_host_when_fuzzing_vhost(self):
        _m, headers, _b = parse_request("GET / HTTP/1.1\r\nHost: FUZZ.example.com\r\n\r\n")
        self.assertEqual(headers, [("Host", "FUZZ.example.com")])


class BuildTests(unittest.TestCase):
    def test_defaults(self):
        m, h, b = parse_request(RAW_GET)
        cmd = build_command(m, "https://example.com/FUZZ", h, b, default_options())
        self.assertEqual(
            cmd,
            'ffuf -u "https://example.com/FUZZ" -H "User-Agent: Mozilla/5.0" -H "Cookie: a=1" '
            '-H "Cookie: b=2" -ac -ic -c -w /usr/share/seclists/Discovery/Web-Content/common.txt')

    def test_post_body_escaped(self):
        m, h, b = parse_request(RAW_POST)
        cmd = build_command(m, "https://example.com/login", h, b, default_options())
        self.assertIn("-X POST", cmd)
        self.assertIn('-d "{\\"user\\":\\"FUZZ\\",\\"p\\":\\"\\$x\\"}"', cmd)

    def test_status_codes_extensions_and_filters(self):
        o = opts(mc=(True, "200,301"), fc=(True, "404"), e=(True, ".php,.bak"),
                 fs=(True, "0"), fr=(True, "Not Found|error"), ac=(False, ""))
        cmd = build_command("GET", "http://t/FUZZ", [], "", o)
        for part in ["-mc 200,301", "-fc 404", "-e .php,.bak", "-fs 0", '-fr "Not Found|error"']:
            self.assertIn(part, cmd)
        self.assertNotIn("-ac", cmd)

    def test_special_flags(self):
        o = opts(recursion=(True, "3"), o=(True, "out.json"), r=(True, ""),
                 x=(True, "http://127.0.0.1:8080"), extra=(True, "-mode clusterbomb"))
        cmd = build_command("GET", "http://t/FUZZ", [], "", o)
        for part in ["-recursion -recursion-depth 3", "-o out.json -of json", " -r ",
                     "-x http://127.0.0.1:8080", "-mode clusterbomb"]:
            self.assertIn(part, cmd)

    def test_checked_but_empty_value_is_skipped(self):
        cmd = build_command("GET", "http://t/FUZZ", [], "", opts(fs=(True, "  ")))
        self.assertNotIn("-fs", cmd)

    def test_empty_wordlist_leaves_w_at_end(self):
        cmd = build_command("GET", "http://t/FUZZ", [], "", opts(w=(True, "")))
        self.assertTrue(cmd.endswith("-w "))

    def test_wordlist_with_space_is_quoted(self):
        cmd = build_command("GET", "http://t/FUZZ", [], "", opts(w=(True, "C:/my lists/a.txt")))
        self.assertTrue(cmd.endswith('-w "C:/my lists/a.txt"'))


if __name__ == "__main__":
    unittest.main()
