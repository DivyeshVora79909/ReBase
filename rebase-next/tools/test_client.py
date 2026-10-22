#!/usr/bin/env python3
"""Focused wire-fault controls, independent of the backend implementation."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import uuid

import client


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.calls.append((self.path, request))
        mode = self.path.rsplit("/", 1)[-1]
        if mode == "lost":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "/rpc/destination")
            self.end_headers()
            return
        result = {"jsonrpc": "2.0", "id": request["id"], "result": {"status": "committed"}}
        if mode == "wrong_id":
            result["id"] = "someone-else"
        if mode == "ambiguous":
            result["error"] = {"message": "bad"}
        if mode == "expired":
            del result["result"]
            result["error"] = {"code": -32000, "message": "Original context expired", "data": {"kind": "operation_expired"}}
        data = json.dumps(result).encode()
        if mode == "duplicate":
            data = data[:-1] + b',"result":null}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data) + (50 if mode == "truncated" else 0)))
        self.end_headers()
        self.wfile.write(data)


class ClientControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        cls.server.calls = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/rpc/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def test_lost_or_invalid_responses_never_retry(self):
        for mode in ("lost", "truncated", "wrong_id", "ambiguous", "duplicate"):
            with self.subTest(mode=mode):
                count = len(self.server.calls)
                with self.assertRaises(client.ClientError) as caught:
                    client.call(self.url + mode, "test-token", "records.mutate", {"operation_id": str(uuid.uuid4())})
                self.assertEqual(caught.exception.kind, "outcome_unknown")
                self.assertEqual(len(self.server.calls), count + 1)

    def test_redirect_does_not_forward_credentials_or_repeat_request(self):
        count = len(self.server.calls)
        with self.assertRaises(client.ClientError) as caught:
            client.call(self.url + "redirect", "test-token", "session.describe", {})
        self.assertEqual(caught.exception.kind, "redirect_rejected")
        self.assertEqual(len(self.server.calls), count + 1)
        self.assertNotEqual(self.server.calls[-1][0], "/rpc/destination")

    def test_expiry_preserves_the_original_request(self):
        request = {"context": "original-context", "operation_id": str(uuid.uuid4())}
        with self.assertRaises(client.RpcError) as caught:
            client.call(self.url + "expired", "test-token", "operations.status", request)
        self.assertEqual(caught.exception.kind, "operation_expired")
        self.assertEqual(self.server.calls[-1][1]["params"], request)

    def test_private_plan_is_complete_and_never_overwrites(self):
        identity = str(uuid.uuid4())
        plan = {"format": client.PLAN_FORMAT,
                "target": {"url": self.url + "ok", "model": "test", "store": identity, "tenant": identity, "actor": identity},
                "request": {"model": "test", "context": "original", "operation_id": identity,
                            "commands": [{"op": "delete", "id": identity, "if_version": "1"}], "returning": []}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.json"
            client.save_plan(path, plan)
            self.assertEqual(client.read_json(path), plan)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                client.save_plan(path, plan)
            self.assertEqual(client.read_json(path), plan)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_invalid_inputs_fail_before_transport(self):
        count = len(self.server.calls)
        for url in ("https://user:password@example.test/rpc", "file:///tmp/rpc", "https://example.test/rpc?token=secret"):
            with self.assertRaises(client.ClientError):
                client.call(url, "test-token", "session.describe", {})
        with self.assertRaises(client.ClientError):
            client.call(self.url, "test-token", "records.mutate", {"large": "a" * 65536})
        with self.assertRaises(client.ClientError):
            client.loads('{"a":1,"a":2}')
        self.assertEqual(len(self.server.calls), count)


if __name__ == "__main__":
    unittest.main()
