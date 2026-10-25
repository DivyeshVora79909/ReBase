#!/usr/bin/env python3
"""G8 bounded operational checks; ordinary importable helpers also work alone."""
import argparse
import json
from pathlib import Path
import sys

from g8_observe import Incomplete
from g8_workload import complete_epoch, database_observer, prepare, preflight, profile, publish_result
from verify_runtime import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "smoke", "churn", "cycles", "overload", "outage", "check"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--backend", choices=("redb", "surrealkv", "foundationdb"), default="redb")
    parser.add_argument("--cluster-file", type=Path)
    parser.add_argument("--database-pid", type=int)
    parser.add_argument("--database-data", type=Path)
    parser.add_argument("--database-log", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--duration", type=float)
    parser.add_argument("--seed", type=int, default=8042)
    args = parser.parse_args()
    state = None
    try:
        if args.command == "check":
            if not args.result:
                parser.error("check requires --result")
            if args.result.name == "pressure-result.json":
                from g8_check import check_pressure_directory
                if args.result.parent.name != "pressure":
                    parser.error("pressure-result.json must remain in its original pressure evidence directory")
                checked = check_pressure_directory(args.result.parent.parent)
            elif args.result.name == "result.json":
                from g8_check import check_directory
                checked = check_directory(args.result.parent)
            elif args.result.name == "outage-result.json":
                from g8_faults import check_outage_directory
                checked = check_outage_directory(args.result.parent)
            else:
                parser.error("check requires result.json, pressure-result.json or outage-result.json and adjacent raw evidence")
            print(json.dumps(checked))
            return 0 if checked["status"] == "passed" else 1 if checked["status"] == "failed" else 2
        if not args.binary:
            parser.error("--binary is required")
        if args.command == "preflight":
            print(json.dumps(preflight(args.binary, args.backend, args.cluster_file), indent=2))
            return 0
        if not args.out:
            parser.error("--out is required and must name a new directory")
        overrides = {"seed": args.seed}
        if args.duration is not None:
            if args.command in ("cycles", "overload", "outage"):
                raise ValueError("Receipt, overload and outage profiles use their own fixed duration budgets")
            overrides["duration_seconds"] = args.duration
        if args.command == "outage" and args.backend != "foundationdb":
            raise ValueError("Database-service outage requires the owned FoundationDB helper")
        settings = profile(smoke=args.command in ("smoke", "overload", "outage"), **overrides)
        database_pid, paths = None, ()
        if args.backend == "foundationdb":
            if not args.cluster_file:
                raise ValueError("FoundationDB requires an explicit cluster file")
            selected = (args.database_pid, args.database_data, args.database_log)
            if any(value is not None for value in selected):
                if any(value is None for value in selected):
                    raise ValueError("Explicit database observations require PID, data and log paths together")
                database_observer(args.database_pid, args.cluster_file, args.database_data, args.database_log)
                database_pid, paths = args.database_pid, (args.database_data, args.database_log)
            else:
                # The disposable helper is the checkout default, not an ambient release import.
                import fdb_cluster
                database_pid, paths = fdb_cluster.server_pid(), (fdb_cluster.DATA, fdb_cluster.LOG)
                database_observer(database_pid, args.cluster_file, *paths)
        elif any(value is not None for value in (args.database_pid, args.database_data, args.database_log)):
            raise ValueError("Database process observations require --backend foundationdb")
        state = prepare(args.binary, args.out, backend=args.backend, cluster_file=args.cluster_file, settings=settings)
        if args.command == "outage":
            from g8_faults import run_outage
            result = run_outage(state)
        elif args.command == "overload":
            from g8_pressure import run_overload
            result = run_overload(state, database_pid=database_pid, database_paths=paths)
        elif args.command == "cycles":
            from g8_cycles import run_cycles
            result = run_cycles(state, database_pid=database_pid, database_paths=paths)
        else:
            result = complete_epoch(state, database_pid=database_pid, database_paths=paths)
            if args.command == "churn":
                from g8_cycles import run_cycles
                result["command"] = "churn"
                result["status"] = "incomplete"
                result["receipt_cycles"] = {"status": "incomplete", "count": 0, "path": "cycles-result.json"}
                write_json(state["directory"] / "result.json", result)
                cycles = run_cycles(state, database_pid=database_pid, database_paths=paths)
                result["status"] = "passed"
                result["receipt_cycles"] = {"status": cycles["status"], "count": cycles["cycle_count"],
                                            "path": "cycles-result.json"}
                publish_result(state["directory"] / "result.json", result, state["directory"], settings["budgets"])
        result_path = ("pressure/pressure-result.json" if args.command == "overload" else
                       "outage-result.json" if args.command == "outage" else
                       "cycles-result.json" if args.command == "cycles" else "result.json")
        print(json.dumps({"status": result["status"], "backend": args.backend, "result": str(args.out / result_path)}))
        return 0 if result["status"] == "passed" else 1 if result["status"] == "failed" else 2
    except BaseException as error:
        status = "incomplete" if isinstance(error, Incomplete) else "failed"
        if state is not None:
            write_json(state["directory"] / "failure.json", {"status": status, "type": type(error).__name__, "message": str(error)})
            if (state["directory"] / "result.json").exists():
                current = json.loads((state["directory"] / "result.json").read_text())
                current.update(status=status, command=args.command, failure="failure.json")
                write_json(state["directory"] / "result.json", current)
        print(json.dumps({"status": status, "error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2 if status == "incomplete" else 1
    finally:
        if state is not None:
            state["backend"].stop()


if __name__ == "__main__":
    raise SystemExit(main())
