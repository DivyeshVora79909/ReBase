"""Small shared observations for the workshop's ordinary HTTP scenarios."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time
import uuid

import client
from capacity import scan, snapshot, work_for
from harness import Backend, expect_error, require
from verify_oracles import OracleError, evaluate, stage


class Mismatch(AssertionError):
    def __init__(self, kind, expected, observed):
        self.kind, self.expected, self.observed = kind, expected, observed
        super().__init__(f"{kind}: expected {expected!r}; observed {observed!r}")


def equal(kind, expected, observed):
    if expected != observed:
        raise Mismatch(kind, expected, observed)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, value):
    path = Path(path)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


class Scenario:
    """One disposable store, its authored facts and a readable assertion log.

    This is tooling around Backend/client, never a second mutation implementation.
    Expected arithmetic is supplied by the separate source-only oracle module.
    """

    def __init__(self, binary, directory, model, name):
        self.backend = Backend(binary, directory, model=model)
        self.name, self.selector = name, model
        self.facts, self.steps, self.labels = {}, [], {}
        self.namespace = uuid.uuid5(uuid.NAMESPACE_URL, "rebase-workshop/" + name)
        try:
            self.backend.start()
            self.catalog = self.backend.call("model.describe", {})
            self.model = self.catalog["model"]
            self.roles = {}
        except BaseException:
            # Construction has not returned, so the caller cannot reach close().
            self.backend.stop()
            raise

    def identity(self, label):
        self.labels[label] = str(uuid.uuid5(self.namespace, label))
        return self.labels[label]

    def create(self, label, contract, fields):
        return {"op": "create", "id": self.identity(label), "contract": contract, "fields": fields}

    def get(self, identity):
        return self.backend.call("records.get", {"model": self.model, "id": identity})

    def update(self, identity, fields):
        return {"op": "update", "id": identity, "if_version": self.get(identity)["version"],
                "set": fields, "unset": []}

    def delete(self, identity):
        return {"op": "delete", "id": identity, "if_version": self.get(identity)["version"]}

    def public(self):
        expectation = evaluate(self.selector, self.facts)
        records = {row["id"]: row for row in scan(self.backend, self.model, len(self.facts))}
        equal("public.inventory", sorted(self.facts), sorted(records))
        for identity, fact in self.facts.items():
            equal("public.input", fact["fields"], records[identity]["input"])
            equal("public.contract", fact["contract"], records[identity]["contract"])
            equal("public.derived", expectation["derived"].get(identity), records[identity]["derived"])
        for root in expectation["roots"]:
            observed = self.backend.call("roots.read", {"model": self.model,
                "owner": root["owner"], "slot": root["slot"], "read": {"kind": "summary"}})["value"]
            for key, expected in root["summary"].items():
                equal("root." + key, expected, observed[key])
        return records, expectation

    def internal(self, label):
        backend = self.backend
        backend.stop()
        try:
            checked = backend.cli("check", backend.store)
            observed = backend.cli("inspect", backend.store)
            write_json(backend.directory / f"{label}.inspect.json", observed)
        finally:
            backend.start()
        for role in observed["roles"]:
            address = json.dumps(role["source_role"], sort_keys=True)
            binding = role["binding"]
            if address in self.roles:
                # Retirement is a separate state; identity is retained.
                equal("role.identity", self.roles[address]["output"], binding["output"])
            self.roles[address] = binding
        return {"check": checked, "records": len(observed["records"]),
                "roots": observed["roots"], "queries": observed["queries"], "roles": observed["roles"]}

    def mutate(self, label, intent, commands, dependency, *, reject=None, literals=None):
        before_facts = deepcopy(self.facts)
        proposal, oracle_error = None, None
        try:
            proposal = stage(self.facts, commands)
            expectation = evaluate(self.selector, proposal)
        except OracleError as error:
            oracle_error = error.kind
        if reject is None and oracle_error:
            raise Mismatch("oracle.unexpected_rejection", "committed", oracle_error)
        if reject is not None and oracle_error != reject:
            raise Mismatch("oracle.rejection", reject, oracle_error or "accepted")
        plan = self.backend.plan({"model": self.model, "commands": commands, "returning": []}, label)
        item = {"name": label, "intent": intent, "method": "records.mutate", "plan": plan,
                "dependency": dependency, "expected": reject or "committed", "oracle_rejection": oracle_error,
                "before_facts": before_facts, "literals": literals or {}}
        self.steps.append(item)
        write_json(self.backend.directory / "steps.json", self.steps)
        started = time.monotonic()
        try:
            if reject:
                before = snapshot(self.backend, label + "-before")
                expect_error(reject, lambda: client.execute(self.backend.url, self.backend.token, plan))
                after = snapshot(self.backend, label + "-after")
                # Complete backups remain private; never print runtime signing material.
                equal("rollback.all_application_tables", hashlib.sha256(client._bytes(before)).hexdigest(),
                      hashlib.sha256(client._bytes(after)).hexdigest())
                equal("rollback.receipt", "not_observed", client.execute(
                    self.backend.url, self.backend.token, plan, status=True)["status"])
                item.update(observed=reject, complete_rollback=True, receipt="not_observed")
            else:
                response = client.execute(self.backend.url, self.backend.token, plan)
                equal("mutation.status", "committed", response["status"])
                self.facts = proposal
                records, expectation = self.public()
                for identity, expected in (literals or {}).items():
                    equal("literal." + identity, expected, records[identity]["derived"])
                item.update(observed="committed", result=response, expected_state=expectation,
                            observed_records=records, work=work_for(self.backend, plan["request"]["operation_id"]))
        except Exception as error:
            item.update(failure={"type": type(error).__name__, "message": str(error)},
                        duration_seconds=round(time.monotonic() - started, 6),
                        after_facts=deepcopy(self.facts))
            write_json(self.backend.directory / "steps.json", self.steps)
            raise
        item["duration_seconds"] = round(time.monotonic() - started, 6)
        item["internal"] = self.internal(label)
        item["after_facts"] = deepcopy(self.facts)
        write_json(self.backend.directory / "steps.json", self.steps)
        return item

    def finish(self):
        return {"name": self.name, "model_selector": self.selector, "model": self.model,
                "catalog": self.catalog, "labels": self.labels, "status": "passed",
                "steps": self.steps, "facts": self.facts,
                "scope": "one isolated model/store; final values and work totals, not an execution trace"}

    def close(self):
        self.backend.stop()
