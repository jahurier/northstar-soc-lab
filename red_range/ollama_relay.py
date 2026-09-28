"""Fixed-path Ollama relay for the isolated Red Range network.

The relay is the only dual-homed range service. It never accepts a destination
from its client and never logs request or response bodies.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "http://host.docker.internal:11434"
GET_PATHS = frozenset(("/api/tags", "/api/version", "/api/ps"))
POST_PATHS = frozenset(("/api/chat", "/api/generate", "/api/show", "/api/embed"))
MAX_REQUEST = 4_000_000
MAX_RESPONSE = 16_000_000


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def _forward(self, allowed: frozenset[str]) -> None:
        if self.path not in allowed:
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > MAX_REQUEST:
            self.send_error(413)
            return
        body = self.rfile.read(size) if self.command == "POST" else None
        request = urllib.request.Request(UPSTREAM + self.path, data=body, method=self.command,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                payload = response.read(MAX_RESPONSE + 1)
                if len(payload) > MAX_RESPONSE:
                    self.send_error(502)
                    return
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except (urllib.error.URLError, TimeoutError):
            self.send_error(502)

    def do_GET(self) -> None:
        self._forward(GET_PATHS)

    def do_POST(self) -> None:
        self._forward(POST_PATHS)


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 11434), Handler).serve_forever()


if __name__ == "__main__":
    main()
