"""Create an idempotent Northstar data view for Kibana Discover."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request

from .setup import load_env

URL = "http://127.0.0.1:5601"
VIEW_ID = "northstar-events"


def request(method: str, path: str, body: dict | None = None) -> dict:
    password = load_env()["ELASTIC_PASSWORD"]
    credential = base64.b64encode(f"elastic:{password}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method,
                                 headers={"Authorization": "Basic " + credential,
                                          "Content-Type": "application/json", "kbn-xsrf": "northstar-lab"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def configure(retries: int = 60) -> None:
    for attempt in range(retries):
        try:
            status = request("GET", "/api/status")
            if status.get("status", {}).get("overall", {}).get("level") == "available":
                break
        except (OSError, urllib.error.URLError, TimeoutError):
            pass
        if attempt == retries - 1:
            raise RuntimeError("Kibana did not become available")
        time.sleep(2)
    try:
        request("GET", f"/api/data_views/data_view/{VIEW_ID}")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        request("POST", "/api/data_views/data_view",
                {"data_view": {"id": VIEW_ID, "name": "Northstar events",
                               "title": "northstar-events-*", "timeFieldName": "@timestamp"}})
    current = request("GET", "/api/data_views/default")
    if not current.get("data_view_id"):
        request("POST", "/api/data_views/default", {"data_view_id": VIEW_ID})


if __name__ == "__main__":
    configure()
    print("Northstar Kibana data view ready; credentials hidden")
