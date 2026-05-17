#!/usr/bin/env python3
"""
Minimal Tenuo Cloud mock server for testing hermes-tenuo Cloud features.
Mimics: POST /v1/triggers/{id}/fire and POST/GET /v1/approvals/requests

Usage:
    python mock_cloud.py

Then in another terminal:
    export TENUO_CONNECT_TOKEN=$(python mock_cloud.py --print-token)
    hermes-tenuo mint --trigger trig_demo
"""

import argparse
import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def make_token(endpoint: str, api_key: str) -> str:
    payload = json.dumps({"v": 1, "e": endpoint, "k": api_key}).encode()
    return "tenuo_ct_" + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def run_server():
    from tenuo import SigningKey, Warrant, Wildcard

    issuer_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("web_search", query=Wildcard())
        .capability("read_file")
        .ttl(3600)
        .mint(issuer_key)
    )

    WARRANT_B64 = base64.b64encode(warrant.to_bytes()).decode()
    WARRANT_ID = "wrt_mock_" + issuer_key.public_key.to_bytes().hex()[:8]
    ISSUER_B64 = base64.b64encode(issuer_key.public_key.to_bytes()).decode()
    AGENT_KEY_B64 = base64.b64encode(agent_key.secret_key_bytes()).decode()

    TOKEN = make_token("http://127.0.0.1:18765", "tc_mock_key")
    approval_requests = {}

    print("═" * 60)
    print("  Tenuo Cloud Mock Server")
    print("═" * 60)
    print(f"\n  Listening:  http://127.0.0.1:18765/v1")
    print(f"\n  Connect token (copy this):")
    print(f"  {TOKEN}")
    print(f"\n  Trigger ID to use: trig_demo")
    print(f"\n  After minting, set:")
    print(f"  export TENUO_SIGNING_KEY={AGENT_KEY_B64}")
    print(f"\n  Issued warrant allows: web_search, read_file")
    print("═" * 60)
    print()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _json(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}

            if "/triggers/" in self.path and self.path.endswith("/fire"):
                tid = self.path.split("/triggers/")[1].split("/fire")[0]
                print(f"  → trigger fire: {tid}")
                sys.stdout.flush()
                self._json(200, {
                    "warrant": WARRANT_B64,
                    "warrant_id": WARRANT_ID,
                    "expires_at": "2027-01-01T00:00:00Z",
                })

            elif self.path.endswith("/approvals/requests"):
                req_id = "req_mock_001"
                tool = body.get("tool", "?")
                approval_requests[req_id] = {"status": "pending", "tool": tool, "responses": []}
                print(f"  → approval request: tool={tool}, id={req_id}")
                sys.stdout.flush()

                def auto_approve():
                    import time
                    time.sleep(2)
                    approval_requests[req_id]["status"] = "approved"
                    print(f"  → auto-approved: {req_id}")
                    sys.stdout.flush()

                threading.Thread(target=auto_approve, daemon=True).start()
                self._json(201, {"id": req_id, "status": "pending", "tool": tool})

            else:
                self._json(404, {"error": "not found"})

        def do_GET(self):
            if "/approvals/requests/" in self.path:
                req_id = self.path.split("/approvals/requests/")[1]
                req = approval_requests.get(req_id, {"status": "pending"})
                self._json(200, req)
            else:
                self._json(404, {"error": "not found"})

    server = HTTPServer(("127.0.0.1", 18765), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-token", action="store_true")
    args = parser.parse_args()
    if args.print_token:
        print(make_token("http://127.0.0.1:18765", "tc_mock_key"))
    else:
        run_server()
