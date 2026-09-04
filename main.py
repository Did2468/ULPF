import json

from ulpf.core.dispatcher import LogDispatcher
from ulpf.core.models import ParserContext
import ulpf.parsers  # important: registers all parsers


def demo():
    dispatcher = LogDispatcher()

    raw = '{"ts":1715688013.171691,"uid":"CQlJW9h6Vyj8RLmwQi","id.orig_h":"10.44.10.22","id.orig_p":53725,"id.resp_h":"10.44.20.10","id.resp_p":53,"proto":"udp","service":"dns","duration":0.000956,"orig_bytes":62,"resp_bytes":90,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"Dd","orig_pkts":1,"orig_ip_bytes":90,"resp_pkts":1,"resp_ip_bytes":118,"ip_proto":17}'
    result = dispatcher.dispatch("zeek.conn", raw, ParserContext(source_type="zeek.conn", reference_year=2024))
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    demo()