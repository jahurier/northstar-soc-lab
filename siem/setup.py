"""Generate local Elastic credentials and configure Kibana's service account.

Never prints credentials. The generated siem/.env is ignored by Git and mode 0600.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

ENV = Path(__file__).with_name(".env")
URL = "http://127.0.0.1:9200"
NAMES = ("ELASTIC_PASSWORD", "KIBANA_PASSWORD", "KIBANA_ENCRYPTION_KEY",
         "KIBANA_SAVEDOBJECTS_KEY", "KIBANA_REPORTING_KEY")


def initialize(path: Path = ENV) -> None:
    if path.exists():
        raise FileExistsError(f"{path} already exists; keeping its credentials")
    values = {name: secrets.token_hex(24) for name in NAMES}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")


def load_env(path: Path = ENV) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        values[name] = value
    if not all(values.get(name) for name in NAMES):
        raise ValueError("siem/.env is incomplete")
    return values


def request(method: str, path: str, body: dict | None, password: str,
            url: str = URL) -> dict:
    credential = base64.b64encode(f"elastic:{password}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url + path, data=data, method=method,
                                 headers={"Authorization": "Basic " + credential,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def configure_kibana(path: Path = ENV, url: str = URL, retries: int = 60) -> None:
    values = load_env(path)
    for attempt in range(retries):
        try:
            request("GET", "/_cluster/health", None, values["ELASTIC_PASSWORD"], url)
            break
        except (OSError, urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise RuntimeError("Elasticsearch did not become ready") from None
            time.sleep(2)
    request("POST", "/_security/user/kibana_system/_password",
            {"password": values["KIBANA_PASSWORD"]}, values["ELASTIC_PASSWORD"], url)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("init", "configure-kibana"))
    args = parser.parse_args()
    if args.action == "init":
        if ENV.exists():
            load_env()
            print("Existing siem/.env kept; credentials hidden")
        else:
            initialize()
            print("Created siem/.env (mode 0600); credentials hidden")
    else:
        configure_kibana()
        print("Configured Kibana service account; credentials hidden")


if __name__ == "__main__":
    main()
