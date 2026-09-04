import unittest
from pathlib import Path

from ulpf.core.dispatcher import LogDispatcher
from ulpf.core.models import ParserContext


class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dispatcher = LogDispatcher()
        cls.root = Path(__file__).resolve().parent.parent

    def _run_file(self, filename: str, source_type: str, expected_min_status="success"):
        path = self.root / filename
        self.assertTrue(path.exists(), f"Missing file: {path}")

        with path.open("r", encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]

        self.assertGreater(len(lines), 0, f"No log lines found in {filename}")

        for i, line in enumerate(lines[:5]):  # test first 5 lines first
            with self.subTest(file=filename, line=i + 1):
                result = self.dispatcher.dispatch(
                    source_type,
                    line,
                    ParserContext(source_type=source_type, reference_year=2024),
                )
                self.assertIn(result.parse_status, ["success", "partial"])
                self.assertTrue(result.raw_event)
                self.assertTrue(result.normalized)
                self.assertIn("event", result.normalized)
                self.assertIn("raw_event", result.to_dict())

    def test_conn_json(self):
        self._run_file("conn.json", "conn.json")

    def test_dns_json(self):
        self._run_file("dns.json", "dns.json")

    def test_http_json(self):
        self._run_file("http.json", "http.json")

    def test_cisco_asa(self):
        self._run_file("cisco_asa.log", "cisco_asa")

    def test_proxy_access(self):
        self._run_file("proxy_access.log", "proxy_access")

    def test_syslog(self):
        self._run_file("syslog.log", "syslog")

    def test_syslog_copy(self):
        self._run_file("syslog copy.log", "syslog")

    def test_web_access(self):
        self._run_file("web_access.log", "web_access")

    def test_snort_alert(self):
        self._run_file("snort_alert.log", "snort_alert")


if __name__ == "__main__":
    unittest.main()