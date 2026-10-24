"""Bounded Linux observations and independent workload resource checks.

These functions neither drive mutations nor infer unsupported engine counters.
The caller owns each observed PID and declares budgets before starting a run.
"""

from collections import deque
import json
import math
import os
from pathlib import Path
import resource
import time

import client
from harness import process_usage


DEFAULT_BUDGETS = {
    "app_rss_kib": 524288,
    "controller_rss_kib": 524288,
    "database_rss_kib": 1048576,
    "app_fds": 256,
    "controller_fds": 128,
    "database_fds": 512,
    "app_threads": 96,
    "controller_threads": 32,
    "database_threads": 64,
    "physical_growth_bytes": 536870912,
    "artifacts_bytes": 134217728,
    "trace_bytes": 33554432,
    "samples_bytes": 8388608,
    "sample_gap_seconds": 3.0,
    "observer_ms": 250.0,
    "cooldown_growth_kib": 16384,
    "db_cooldown_growth_kib": 65536,
}


class Incomplete(RuntimeError):
    """A required observation or evidence stream could not be completed."""


def validate_budgets(budgets):
    """Require a complete, explicit set of finite positive resource budgets."""
    if not isinstance(budgets, dict) or set(budgets) != set(DEFAULT_BUDGETS):
        raise ValueError("resource budgets require exactly the documented budget fields")
    for name, value in budgets.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a positive finite number")
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be a positive finite number")
    return dict(budgets)


def host_limits():
    """Record actual host/process limits; missing cgroup values stay unavailable."""
    memory = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                memory[key] = int(value.split()[0])
    except OSError:
        pass
    cgroup = {}
    for name in ("memory.max", "memory.current", "cpu.max", "pids.max"):
        try:
            cgroup[name] = Path("/sys/fs/cgroup", name).read_text().strip()
        except OSError:
            cgroup[name] = None
    limits = {}
    for label, number in (("nofile", resource.RLIMIT_NOFILE), ("nproc", resource.RLIMIT_NPROC)):
        soft, hard = resource.getrlimit(number)
        limits[label] = {"soft": soft, "hard": hard}
    return {"memory_kib": memory, "cpu_count": os.cpu_count(),
            "affinity_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "cgroup": cgroup, "process_limits": limits, "platform": os.uname().sysname}


def process_sample(pid):
    """Reuse the harness RSS/FD observer and add PID identity and CPU usage."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("an owned positive PID is required")
    try:
        result = process_usage(pid)
        if not result["available"]:
            return {"available": False, "pid": pid}
        # comm may contain spaces or closing parentheses; fields after the final
        # parenthesis begin at stat field 3. utime/stime/starttime are 14/15/22.
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rfind(")") + 2:].split()
        return {**result, "pid": pid, "start_ticks": int(fields[19]),
                "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")}
    except (OSError, KeyError, ValueError, IndexError):
        # Exit between the independent /proc reads is an incomplete observation.
        return {"available": False, "pid": pid}


def physical_sample(paths, max_files=65536):
    """Observe real files, once per inode, including explicit owned DB/log paths."""
    roots = sorted({Path(path).resolve() for path in paths}, key=lambda path: (len(path.parts), str(path)))
    if not roots:
        return {"available": False, "bytes": None, "paths": [], "files": 0}
    selected = []
    for root in roots:
        if not any(root == parent or root.is_relative_to(parent) for parent in selected):
            selected.append(root)
    seen, size, count, visited = set(), 0, 0, 0
    try:
        for root in selected:
            if not root.exists():
                raise OSError("observation path does not exist")
            candidates = root.rglob("*") if root.is_dir() else (root,)
            for path in candidates:
                visited += 1
                if visited > max_files:
                    raise OSError("physical observation file budget exhausted")
                if path.is_file():
                    stat = path.stat()
                    identity = (stat.st_dev, stat.st_ino)
                    if identity not in seen:
                        seen.add(identity)
                        size += stat.st_size
                        count += 1
    except OSError:
        # A vanished WAL segment is a sample gap, not evidence of zero usage.
        return {"available": False, "bytes": None, "paths": [str(path) for path in selected], "files": count}
    return {"available": True, "bytes": size, "paths": [str(path) for path in selected], "files": count}


def sample(application_pid, controller_pid, database_pid=None, paths=(), phase="measurement", logical=None):
    started = time.monotonic()
    processes = {"application": process_sample(application_pid), "controller": process_sample(controller_pid)}
    if database_pid is not None:
        processes["database"] = process_sample(database_pid)
    physical = physical_sample(paths)
    return {"timestamp": time.time(), "monotonic_seconds": started, "phase": phase,
            "processes": processes, "physical": physical, "physical_bytes": physical["bytes"],
            "logical": logical, "observer_ms": (time.monotonic() - started) * 1000}


class JsonlWriter:
    """Exclusive private evidence stream that never silently truncates a run."""

    def __init__(self, path, max_bytes):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")
        self.path, self.max_bytes = Path(path), max_bytes
        self.bytes, self.count = 0, 0
        self.output = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")

    def write(self, value):
        data = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if self.bytes + len(data) > self.max_bytes:
            raise Incomplete(f"required evidence byte budget exhausted: {self.path.name}")
        self.output.write(data)
        self.output.flush()
        self.bytes += len(data)
        self.count += 1

    def close(self):
        self.output.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def read_jsonl(path, max_bytes, max_rows):
    """Stream complete evidence under explicit byte and row limits."""
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
           for value in (max_bytes, max_rows)):
        raise ValueError("positive byte and row limits are required")
    used, rows = 0, 0
    try:
        with Path(path).open("rb") as source:
            while True:
                line = source.readline(max_bytes - used + 1)
                if not line:
                    return
                used += len(line)
                rows += 1
                if used > max_bytes or rows > max_rows:
                    raise Incomplete("required evidence exceeds declared read budget")
                if not line.endswith(b"\n"):
                    raise Incomplete("required evidence contains an incomplete JSONL row")
                try:
                    value = client.loads(line)
                except (client.ClientError, UnicodeError) as error:
                    raise Incomplete("required evidence contains an invalid JSONL row") from error
                if not isinstance(value, dict):
                    raise Incomplete("required evidence row must be an object")
                yield value
    except OSError as error:
        raise Incomplete("required evidence stream is unavailable") from error


def check_artifacts(directory, budgets):
    budgets = validate_budgets(budgets)
    observation = physical_sample((directory,))
    status = "incomplete" if not observation["available"] else (
        "passed" if observation["bytes"] <= budgets["artifacts_bytes"] else "failed")
    return {"status": status, "bytes": observation["bytes"], "budget_bytes": budgets["artifacts_bytes"]}


def check_resources(samples, budgets, require_database=False):
    """Check absolute bounds and comparable cooldown growth in one streaming pass.

    State is bounded independently of duration: process peaks, first/last ten
    cooldown samples, and short problem descriptions. A missing trend window is
    reported unsupported; it cannot erase required absolute-budget results.
    """
    budgets = validate_budgets(budgets)
    obligations, peaks, problems = {}, {}, []
    names = ("application", "controller", "database") if require_database else ("application", "controller")
    mapping = {"application": "app", "controller": "controller", "database": "database"}
    count, previous, max_gap, observer_peak = 0, None, 0.0, 0.0
    base_physical, max_physical, missing_physical = None, None, False
    identity, switched, missing_roles = None, False, set()
    cooldown_first, cooldown_last, cooldown_count = [], deque(maxlen=10), 0
    cooldown_inventory, cooldown_identities, comparable = None, {}, True

    def problem(message):
        if message not in problems and len(problems) < 12:
            problems.append(message)

    try:
        for row in samples:
            count += 1
            if not isinstance(row, dict):
                problem("sample is not an object")
                continue
            moment, overhead = row.get("monotonic_seconds"), row.get("observer_ms")
            if not isinstance(moment, (int, float)) or isinstance(moment, bool) or not math.isfinite(moment):
                problem("missing or invalid monotonic time")
            else:
                if previous is not None:
                    gap = moment - previous
                    if gap <= 0:
                        problem("sample times do not increase")
                    max_gap = max(max_gap, gap)
                previous = moment
            if not isinstance(overhead, (int, float)) or isinstance(overhead, bool) or not math.isfinite(overhead) or overhead < 0:
                problem("missing or invalid observer duration")
            else:
                observer_peak = max(observer_peak, overhead)
            physical = row.get("physical_bytes")
            if isinstance(physical, bool) or not isinstance(physical, int) or physical < 0:
                missing_physical = True
            else:
                if base_physical is None:
                    base_physical = physical
                max_physical = max(max_physical or 0, physical)
            processes = row.get("processes", {})
            if not isinstance(processes, dict):
                problem("missing process observation object")
                processes = {}
            for name in names:
                observed = processes.get(name)
                fields = ("pid", "start_ticks", "rss_kib", "peak_rss_kib", "cpu_seconds", "open_fds", "threads")
                if not isinstance(observed, dict) or observed.get("available") is not True or any(
                        isinstance(observed.get(key), bool) or not isinstance(observed.get(key), (int, float))
                        or not math.isfinite(observed[key]) or observed[key] < 0 for key in fields):
                    missing_roles.add(name)
                    continue
                peak = peaks.setdefault(name, {"rss_kib": 0, "peak_rss_kib": 0, "open_fds": 0, "threads": 0,
                                               "cpu_first_seconds": observed["cpu_seconds"], "cpu_last_seconds": observed["cpu_seconds"]})
                for field in ("rss_kib", "peak_rss_kib", "open_fds", "threads"):
                    peak[field] = max(peak[field], observed[field])
                peak["cpu_last_seconds"] = observed["cpu_seconds"]
                if name == "application" and row.get("phase") in ("warmup", "measurement", "cooldown"):
                    current = (observed["pid"], observed["start_ticks"])
                    if identity is None:
                        identity = current
                    elif current != identity:
                        switched = True
            if row.get("phase") == "cooldown":
                cooldown_count += 1
                inventory = row.get("logical")
                if not isinstance(inventory, dict):
                    comparable = False
                elif cooldown_inventory is None:
                    cooldown_inventory = dict(inventory)
                elif inventory != cooldown_inventory:
                    comparable = False
                for name in names:
                    observed = processes.get(name, {})
                    current = (observed.get("pid"), observed.get("start_ticks"))
                    if not observed.get("available") or None in current:
                        comparable = False
                    elif name not in cooldown_identities:
                        cooldown_identities[name] = current
                    elif current != cooldown_identities[name]:
                        comparable = False
                saved = {"processes": processes, "physical_bytes": physical}
                if len(cooldown_first) < 10:
                    cooldown_first.append(saved)
                cooldown_last.append(saved)
    except Incomplete as error:
        problem(str(error))

    observations = "incomplete" if count < 2 or problems or missing_roles or missing_physical else "passed"
    obligations["observations"] = {"status": observations, "required": True, "problems": problems,
                                   "missing_processes": sorted(missing_roles), "missing_physical": missing_physical}
    obligations["sample_gap"] = {"status": "failed" if max_gap > budgets["sample_gap_seconds"] else "passed",
                                 "required": True, "max_seconds": max_gap, "budget_seconds": budgets["sample_gap_seconds"]}
    obligations["continuous_application_pid"] = {"status": "failed" if switched else ("passed" if identity else "unsupported"),
                                                   "required": True, "identity": list(identity) if identity else None}
    obligations["observer_overhead"] = {"status": "failed" if observer_peak > budgets["observer_ms"] else "passed",
                                        "required": True, "peak_ms": observer_peak, "budget_ms": budgets["observer_ms"]}
    for name in names:
        prefix, peak = mapping[name], peaks.get(name)
        limits = {"rss_kib": budgets[prefix + "_rss_kib"], "open_fds": budgets[prefix + "_fds"],
                  "threads": budgets[prefix + "_threads"]}
        status = "incomplete" if name in missing_roles or peak is None else "passed"
        if peak and (max(peak["rss_kib"], peak["peak_rss_kib"]) > limits["rss_kib"]
                     or peak["open_fds"] > limits["open_fds"] or peak["threads"] > limits["threads"]):
            status = "failed"
        obligations[name + "_resources"] = {"status": status, "required": True, "peaks": peak, "budgets": limits}
    if not require_database:
        obligations["database_resources"] = {"status": "unsupported", "required": False,
                                               "reason": "no separate database PID required by this profile"}
    growth = None if base_physical is None else max(0, max_physical - base_physical)
    obligations["physical_growth"] = {"status": "incomplete" if missing_physical or growth is None else (
        "failed" if growth > budgets["physical_growth_bytes"] else "passed"), "required": True,
        "growth_bytes": growth, "initial_bytes": base_physical, "peak_bytes": max_physical,
        "budget_bytes": budgets["physical_growth_bytes"]}

    cooldown = {"status": "unsupported", "required": False, "samples": cooldown_count,
                "reason": "at least six cooldown samples with constant logical inventory are required"}
    if comparable and cooldown_count >= 6 and cooldown_inventory is not None:
        width = min(10, cooldown_count // 3)
        first, last = cooldown_first[:width], list(cooldown_last)[-width:]
        growth_by_process = {}
        for name in names:
            try:
                early = sum(row["processes"][name]["rss_kib"] for row in first) / width
                late = sum(row["processes"][name]["rss_kib"] for row in last) / width
                growth_by_process[name] = max(0, late - early)
            except (KeyError, TypeError):
                missing_roles.add(name)
        if len(growth_by_process) == len(names):
            limits = {name: budgets["db_cooldown_growth_kib" if name == "database" else "cooldown_growth_kib"] for name in names}
            cooldown = {"status": "failed" if any(value > limits[name] for name, value in growth_by_process.items()) else "passed",
                        "required": False, "samples": cooldown_count, "window_samples": width,
                        "growth_kib": growth_by_process, "budgets_kib": limits, "logical": cooldown_inventory,
                        "scope": "comparable read-only cooldown windows; no longer soak or leak-freedom claim"}
    obligations["cooldown_growth"] = cooldown
    status = "failed" if any(item["status"] == "failed" for item in obligations.values()) else (
        "incomplete" if any(item["required"] and item["status"] != "passed" for item in obligations.values()) else "passed")
    return {"status": status, "obligations": obligations, "sample_count": count, "peaks": peaks, "cooldown": cooldown}
