import unittest

from ulpf.core.dispatcher import LogDispatcher
from ulpf.core.models import ParserContext


class TestSmoke(unittest.TestCase):
    def test_list_sources_work(self):
        dispatcher = LogDispatcher()
        self.assertIn("zeek.conn", dispatcher.supported_source_types())

    def test_conn_parse(self):
        dispatcher = LogDispatcher()
        raw = '{"ts":1715688013.171691,"uid":"CQlJW9h6Vyj8RLmwQi","id.orig_h":"10.44.10.22","id.orig_p":53725,"id.resp_h":"10.44.20.10","id.resp_p":53,"proto":"udp","service":"dns","duration":0.000956,"orig_bytes":62,"resp_bytes":90,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"Dd","orig_pkts":1,"orig_ip_bytes":90,"resp_pkts":1,"resp_ip_bytes":118,"ip_proto":17}'
        result = dispatcher.dispatch("conn.json", raw, ParserContext(source_type="conn.json"))
        self.assertEqual(result.parse_status, "success")
        self.assertEqual(result.normalized["source"]["ip"], "10.44.10.22")


if __name__ == "__main__":
    unittest.main()