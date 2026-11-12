"""OpenAI-compatible scripted model for the D0 spike. A task line "CALL <tool> <json>" becomes that
tool call, in order; then it answers with the tool results. Every request is logged."""

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("MODEL_LOG", "/lab/model_requests.jsonl")
CALL = re.compile(r"^CALL (\S+) (\{.*\})\s*$", re.M)


class Model(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json"):
        wire = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def do_GET(self):
        self._send(json.dumps({"object": "list", "data": [{"id": "stub", "object": "model"}]}))

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with open(LOG, "a") as fh:
            fh.write(json.dumps(body) + "\n")
        msgs = body.get("messages", [])
        def text_of(m):
            c = m.get("content", "")
            return " ".join(p.get("text", "") for p in c if isinstance(p, dict)) if isinstance(c, list) else (c or "")
        # Anchor on the user message that carries the script; Hermes may add other user-role notes.
        scripted = [i for i, m in enumerate(msgs) if m.get("role") == "user" and "CALL " in text_of(m)]
        last_user = scripted[-1] if scripted else max(
            (i for i, m in enumerate(msgs) if m.get("role") == "user"), default=-1)
        user = text_of(msgs[last_user]) if last_user >= 0 else ""
        calls = CALL.findall(user or "")
        done = sum(len(m.get("tool_calls") or []) for m in msgs[last_user + 1:] if m.get("role") == "assistant")
        if done < len(calls):
            name, args = calls[done]
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"call_{done}", "type": "function", "function": {"name": name, "arguments": args}}]}
            finish = "tool_calls"
        else:
            results = [str(m.get("content", ""))[:200] for m in msgs[last_user + 1:] if m.get("role") == "tool"]
            message = {"role": "assistant", "content": "RESULTS: " + " | ".join(results) if results else "No tools needed."}
            finish = "stop"
        if body.get("stream"):
            delta = dict(message)
            if "tool_calls" in delta:
                delta["tool_calls"] = [{"index": i, **c} for i, c in enumerate(delta["tool_calls"])]
            chunks = [{"id": "s", "object": "chat.completion.chunk", "created": 1, "model": "stub",
                       "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                      {"id": "s", "object": "chat.completion.chunk", "created": 1, "model": "stub",
                       "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                       "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}]
            self._send("".join("data: " + json.dumps(c) + "\n\n" for c in chunks) + "data: [DONE]\n\n",
                       "text/event-stream")
        else:
            self._send(json.dumps({"id": "s", "object": "chat.completion", "created": 1, "model": "stub",
                                   "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                                   "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}))


ThreadingHTTPServer(("0.0.0.0", 8080), Model).serve_forever()
