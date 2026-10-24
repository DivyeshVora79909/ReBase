#!/usr/bin/env python3
"""G8 bounded operational checks; ordinary importable helpers also work alone."""
import argparse
import json
from pathlib import Path
import sys

from g8_observe import Incomplete
from g8_workload import check, complete_epoch, prepare, preflight, profile
from verify_runtime import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "smoke", "churn", "check"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--backend", choices=("redb", "surrealkv", "foundationdb"), default="redb")
    parser.add_argument("--cluster-file", type=Path)
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
            print(json.dumps(check(json.loads(args.result.read_text()))))
            return 0
        if not args.binary:
            parser.error("--binary is required")
        if args.command == "preflight":
            print(json.dumps(preflight(args.binary, args.backend, args.cluster_file), indent=2))
            return 0
        if not args.out:
            parser.error("--out is required and must name a new directory")
        overrides = {"seed": args.seed}
        if args.duration is not None:
            overrides["duration_seconds"] = args.duration
        settings = profile(smoke=args.command == "smoke", **overrides)
        database_pid, paths = None, ()
        if args.backend == "foundationdb":
            # Only observe this helper's server, never infer a namespace is a data path.
            import fdb_cluster
            if args.cluster_file.resolve() != fdb_cluster.CLUSTER.resolve() or not fdb_cluster.server_pid():
                raise ValueError("FoundationDB measurement requires the explicitly owned running helper cluster")
            database_pid, paths = fdb_cluster.server_pid(), (fdb_cluster.DATA, fdb_cluster.LOG)
        state = prepare(args.binary, args.out, backend=args.backend, cluster_file=args.cluster_file, settings=settings)
        result = complete_epoch(state, database_pid=database_pid, database_paths=paths)
        print(json.dumps({"status": result["status"], "backend": args.backend, "result": str(args.out / "result.json")}))
        return 0
    except BaseException as error:
        status = "incomplete" if isinstance(error, Incomplete) else "failed"
        if state is not None:
            write_json(state["directory"] / "failure.json", {"status": status, "type": type(error).__name__, "message": str(error)})
        print(json.dumps({"status": status, "error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2 if status == "incomplete" else 1
    finally:
        if state is not None:
            state["backend"].stop()


if __name__ == "__main__":
    raise SystemExit(main())
