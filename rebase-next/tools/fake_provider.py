#!/usr/bin/env python3
"""Independent, disposable G5 provider. Its SQLite journal survives backend loss.

Only the local acceptance harness writes modes.json and response hold files.
This is a deterministic test service, not a production provider implementation.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import threading
import time
import uuid


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def canonical_uuid(text):
    return isinstance(text, str) and str(uuid.UUID(text)) == text and uuid.UUID(text).int != 0


class Provider(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, directory):
        super().__init__(("127.0.0.1", 0), Handler)
        self.directory = directory
        self.journal = directory / "journal.sqlite"
        self.mutex = threading.Lock()
        self.active = 0
        self.peak = 0
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS executions (
                    execution TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
                    payload TEXT NOT NULL, phase TEXT NOT NULL, receipt TEXT,
                    accepted INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS calls (
                    sequence INTEGER PRIMARY KEY, method TEXT NOT NULL,
                    execution TEXT NOT NULL, request_hash TEXT, phase TEXT,
                    observed_ns INTEGER NOT NULL);
            """)

    def connect(self):
        db = sqlite3.connect(self.journal, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    def visiting(self, delta):
        with self.mutex:
            self.active += delta
            self.peak = max(self.peak, self.active)
            (self.directory / "concurrency.json").write_bytes(encoded({"active": self.active, "peak": self.peak}))

    def mode(self, execution):
        modes = json.loads((self.directory / "modes.json").read_bytes())
        return modes.get(execution, "success")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        body = encoded(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self.handle_execution(False)

    def do_POST(self):
        self.handle_execution(True)

    def handle_execution(self, submit):
        self.server.visiting(1)
        try:
            self.execute(submit)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.reply(400, {"error": "invalid fake request"})
        finally:
            self.server.visiting(-1)

    def execute(self, submit):
        parts = self.path.split("/")
        if len(parts) != 4 or parts[1] != "executions" or parts[3] != "1" or not canonical_uuid(parts[2]):
            self.reply(404, {"error": "unknown action"})
            return
        execution = parts[2]
        mode = self.server.mode(execution)
        payload, request_hash = None, None
        if submit:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                self.reply(413, {"error": "body limit"})
                return
            payload = json.loads(self.rfile.read(length))
            request = payload["request"]
            if (set(payload) != {"execution_id", "account", "action", "request"}
                    or payload["execution_id"] != execution or payload["account"] != "fake-account-1"
                    or payload["action"] != 1 or set(request) != {"account", "units", "execute_at", "not_after"}
                    or not canonical_uuid(request["account"]) or not isinstance(request["units"], str)
                    or str(int(request["units"])) != request["units"] or not 1 <= int(request["units"]) <= 1_000_000):
                raise ValueError("request binding")
            request_hash = hashlib.sha256(encoded(payload)).hexdigest()

        status = 200
        with self.server.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM executions WHERE execution=?", (execution,)).fetchone()
            if submit and existing is not None and existing["request_hash"] != request_hash:
                phase, status = "conflict", 409
            elif existing is not None:
                payload = json.loads(existing["payload"])
                phase = existing["phase"]
                if phase == "waiting" and mode == "success":
                    phase = "succeeded"
                    db.execute("UPDATE executions SET phase=? WHERE execution=?", (phase, execution))
            elif not submit:
                phase, status = "unknown", 404
            else:
                attempts = db.execute("SELECT count(*) FROM calls WHERE execution=? AND method='POST'", (execution,)).fetchone()[0]
                if mode == "not_accepted" or mode == "reject_once" and attempts == 0:
                    phase = "not_accepted"
                else:
                    phase = "waiting" if mode == "waiting" else "failed" if mode == "failed" else "succeeded"
                    receipt = str(uuid.uuid5(uuid.UUID(execution), "fake-units-1")) if phase != "failed" else None
                    db.execute("INSERT INTO executions VALUES (?,?,?,?,?,?)",
                               (execution, request_hash, encoded(payload).decode(), phase, receipt, int(phase != "failed")))
            if not submit and mode == "empty":
                phase, status = "unknown", 404
            db.execute("INSERT INTO calls(method,execution,request_hash,phase,observed_ns) VALUES (?,?,?,?,?)",
                       ("POST" if submit else "GET", execution, request_hash, phase, time.time_ns()))
            # Context manager commits before any response, disconnect or pause.
        if submit and status == 200 and phase in ("succeeded", "waiting"):
            (self.server.directory / f"{execution}.accepted.json").write_bytes(encoded({"execution": execution, "phase": phase}))
        if submit and mode == "pause_response":
            while (self.server.directory / f"{execution}.response.hold").exists():
                time.sleep(0.025)
        if submit and mode == "lost_response":
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if status != 200:
            self.reply(status, {"error": phase})
        else:
            self.reply(200, {"execution_id": execution, "account": "fake-account-1", "action": 1,
                             "units": payload["request"]["units"], "phase": phase,
                             "receipt": str(uuid.uuid5(uuid.UUID(execution), "fake-units-1"))
                             if phase in ("succeeded", "waiting") else None})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700, exist_ok=True)
    if not (directory / "modes.json").exists():
        (directory / "modes.json").write_text("{}\n")
    server = Provider(directory)
    (directory / "ready.tmp").write_bytes(encoded({"endpoint": f"http://127.0.0.1:{server.server_port}"}))
    (directory / "ready.tmp").replace(directory / "ready.json")
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
