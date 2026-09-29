"""Check that the clean, data-free public snapshot serves its local console."""

from __future__ import annotations

import argparse
import http.client
import json
import threading

from console import server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--imported", action="store_true", help="check the reusable case-import example")
    args = parser.parse_args()
    store = server.Store()
    source = "imported" if args.imported else "simulated"
    assert sum(row["provenance"] == source for row in store.rows) > 0
    httpd = server.make_server(0)
    port = httpd.server_address[1]
    server.Handler.port = port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        for path in ("/", "/api/showcase", "/api/jev-map"):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
            response = conn.getresponse()
            body = response.read()
            conn.close()
            assert response.status == 200, (path, response.status)
            if path == "/api/showcase":
                showcase = json.loads(body)
                assert showcase["environment"] == "local_test_lab"
                assert showcase["saved_comparison"]["cases"] == 23
                assert showcase["saved_comparison"]["arms"]["chain"]["correct"] == 22
                if args.imported:
                    assert showcase["imported"]["cases"] == 2
                    assert showcase["imported"]["state_matched_jev"] == 2
            if path == "/api/jev-map":
                decision_map = json.loads(body)
                if args.imported:
                    assert len(decision_map["catalog"]) == 2
                    assert decision_map["selected"]["model"] == "manual-example"
                    assert decision_map["selected"]["verification"]["policy_match"]
                else:
                    assert decision_map["catalog"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
    print("imported-case review smoke test passed" if args.imported else
          "offline console and API smoke test passed")


if __name__ == "__main__":
    main()
