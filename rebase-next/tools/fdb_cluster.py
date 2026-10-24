#!/usr/bin/env python3
"""Run the ignored local FoundationDB 7.3.69 cluster in target/g7-environment."""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "target" / "g7-environment"
FDBSERVER = ENV / "root" / "usr" / "sbin" / "fdbserver"
FDBCLI = ENV / "root" / "usr" / "bin" / "fdbcli"
CLUSTER = ENV / "fdb.cluster"
DATA = ENV / "data"
LOG = ENV / "log"
PIDFILE = ENV / "server.pid"
HOST, PORT = "127.0.0.1", 4500


def cli(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(FDBCLI), "-C", str(CLUSTER), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=check,
    )


def server_pid() -> int | None:
    try:
        pid = int(PIDFILE.read_text().strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        if str(FDBSERVER).encode() in cmdline:
            return pid
    except (OSError, ValueError):
        pass
    return None


def start() -> None:
    if server_pid():
        print(f"FoundationDB server already running (pid {server_pid()})")
        return
    if not FDBSERVER.is_file() or not CLUSTER.is_file():
        raise SystemExit("FoundationDB runtime is missing; expected target/g7-environment setup")
    DATA.mkdir(parents=True, exist_ok=True)
    LOG.mkdir(parents=True, exist_ok=True)
    output = (ENV / "server.stdout").open("ab")
    proc = subprocess.Popen(
        [
            str(FDBSERVER), "-p", f"{HOST}:{PORT}", "-C", str(CLUSTER),
            "-d", str(DATA), "-L", str(LOG), "-m", "512",
            "--cache-memory", "128", "--storage-memory", "128",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output.close()
    PIDFILE.write_text(f"{proc.pid}\n")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"fdbserver exited; inspect {ENV / 'server.stdout'}")
        try:
            with socket.create_connection((HOST, PORT), timeout=0.3):
                print(f"FoundationDB server listening at {HOST}:{PORT} (pid {proc.pid})")
                return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"fdbserver did not listen; inspect {ENV / 'server.stdout'}")


def stop() -> None:
    pid = server_pid()
    if pid is None:
        print("FoundationDB server is not running")
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            PIDFILE.unlink(missing_ok=True)
            print("FoundationDB server stopped")
            return
        time.sleep(0.2)
    raise SystemExit(f"fdbserver pid {pid} did not stop after SIGTERM; no further signal sent")


def status() -> None:
    result = cli("--exec", "status", check=False)
    sys.stdout.write(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def bootstrap() -> None:
    result = cli("--no-status", "--exec", "configure new single ssd", check=False)
    sys.stdout.write(result.stdout)
    if result.returncode:
        raise SystemExit(result.returncode)


def check() -> None:
    key = f"g7_environment_probe_{os.getpid()}"
    value = "verified"
    command = f"writemode on; begin; set {key} {value}; commit; get {key}; begin; clear {key}; commit"
    result = cli("--exec", command, check=False)
    sys.stdout.write(result.stdout)
    if result.returncode or f"`{key}' is `{value}'" not in result.stdout:
        raise SystemExit(result.returncode or "FoundationDB read/write check did not return the written value")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "stop", "status", "bootstrap", "check"))
    action = parser.parse_args().command
    {"start": start, "stop": stop, "status": status, "bootstrap": bootstrap, "check": check}[action]()


if __name__ == "__main__":
    main()
