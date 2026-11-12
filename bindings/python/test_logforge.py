import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from logforge import LogForge  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "sample.log"


class BindingTests(unittest.TestCase):
    def test_fixture_report(self):
        with LogForge() as lf:
            lf.analyze_file(FIXTURE)
            r = lf.report()
        self.assertEqual((r["lines"], r["parsed"], r["malformed"], r["bytes"]), (32, 29, 3, 23340))
        self.assertEqual(r["status"], {"1xx": 0, "2xx": 11, "3xx": 1, "4xx": 16, "5xx": 1})
        self.assertEqual(r["attacks"], {"sqli": 1, "traversal": 1, "xss": 2, "scanner": 3, "shellshock": 1, "log4shell": 1, "sensitive_file": 2})
        self.assertEqual(r["top_ips"][0], {"ip": "192.0.2.55", "count": 12})
        self.assertEqual(r["auth_failures"], [{"ip": "192.0.2.55", "count": 12}])
        self.assertEqual(r["attack_lines"], 8)

    def test_chunking_does_not_change_the_result(self):
        data = FIXTURE.read_bytes()
        with LogForge() as a:
            a.feed(data)
            whole = a.report()
        for step in (1, 7, 64, 1000):
            with LogForge() as b:
                for i in range(0, len(data), step):
                    b.feed(data[i : i + step])
                self.assertEqual(b.report(), whole, step)

    def test_last_line_without_newline_is_counted(self):
        with LogForge() as lf:
            lf.feed(b'192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"')
            self.assertEqual(lf.report()["parsed"], 1)

    def test_hostile_bytes_yield_valid_json(self):
        with LogForge() as lf:
            lf.feed(b'192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "GET /\xff\xfe\\"\x01 HTTP/1.1" 200 1 "-" "x"\n')
            lf.feed(bytes(range(256)) * 20)
            r = lf.report()
        self.assertEqual(r["parsed"], 1)
        self.assertEqual(r["top_paths"][0]["path"], "/ÿþ\\\"\u0001")

    def test_use_after_close_raises(self):
        lf = LogForge()
        lf.close()
        lf.close()  # idempotent
        with self.assertRaises(ValueError):
            lf.feed(b"x")
        with self.assertRaises(ValueError):
            lf.report()

    def test_many_independent_contexts(self):
        with LogForge() as a, LogForge() as b:
            a.feed(FIXTURE.read_bytes())
            self.assertEqual(b.report()["lines"], 0)
            self.assertEqual(a.report()["lines"], 32)

    def test_table_overflow_is_reported_not_fatal(self):
        with LogForge() as lf:
            lines = []
            for i in range(95000):
                lines.append(('10.%d.%d.%d - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n' % ((i >> 16) & 255, (i >> 8) & 255, i & 255)))
            lf.feed("".join(lines).encode())
            r = lf.report()
        self.assertEqual(r["unique_ips"], 90000)
        self.assertEqual(r["ip_overflow"], 5000)
        self.assertEqual(r["parsed"], 95000)

    def test_cli_script_matches_the_api(self):
        out = subprocess.run([sys.executable, str(Path(__file__).parent / "logforge.py"), str(FIXTURE)], capture_output=True, text=True, check=True).stdout
        with LogForge() as lf:
            lf.analyze_file(FIXTURE)
            self.assertEqual(json.loads(out), lf.report())


if __name__ == "__main__":
    unittest.main()
