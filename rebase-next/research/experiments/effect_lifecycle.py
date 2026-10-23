#!/usr/bin/env python3
"""Independent bounded G5 lifecycle oracle; no Rust/runtime/provider imports.

Logical snapshots model atomic publication, not a database, clock, HTTP server or
distributed scheduler. A separate tiny provider journal makes lost responses and
stale-backup resurrection observable. Run with Python 3.11+, without dependencies.
"""

from copy import deepcopy
from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path


class Rejected(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


@dataclass(frozen=True)
class Request:
    source: str = "dispatch"
    account: str = "account-v1"
    units: int = 3
    due: int = 0
    not_after: int = 100


@dataclass(frozen=True)
class Claim:
    activation: int
    execution: str
    revision: int
    token: str
    until: int
    mode: str


@dataclass(frozen=True)
class Execution:
    request: Request
    phase: str = "ready"
    revision: int = 0
    claim: Claim | None = None
    started: bool = False
    cancel: bool = False
    application: str = "none"
    quarantined: bool = False
    attempts: int = 0


@dataclass
class State:
    balance: int = 10
    authorized: bool = True
    activation: int = 1
    active: bool = True
    executions: dict = field(default_factory=dict)
    operations: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    inbox: dict = field(default_factory=dict)


def unresolved(row):
    return row.phase in {"ready", "waiting", "uncertain"} or row.application in {
        "pending", "blocked"
    }


def submit(state, operation, request=Request(), balance=None, abort=False):
    content = (request, balance)
    if operation in state.operations:
        previous, execution = state.operations[operation]
        require(previous == content, "operation_content_conflict")
        return deepcopy(state), execution
    require(len(state.executions) < 256, "retained_limit")
    require(sum(unresolved(e) for e in state.executions.values()) < 64,
            "unresolved_limit")
    require(state.authorized, "submit_authority")
    require(0 < request.units <= 1000 and request.due < request.not_after,
            "request_shape")
    next_state = deepcopy(state)
    if balance is not None:
        require(balance >= 0, "business_invariant")
        next_state.balance = balance
    execution = operation + "/action-1"
    next_state.executions[execution] = Execution(request)
    next_state.operations[operation] = (content, execution)
    require(not abort, "injected_abort_after_intent")
    return next_state, execution


def claim(state, execution, now, token, mode="submit"):
    next_state = deepcopy(state)
    row = next_state.executions[execution]
    require(state.active, "dispatch_disabled")
    require(row.claim is None or now >= row.claim.until, "lease_live")
    if row.claim is not None:
        # An expired started submission can never become a normal retry.
        row = replace(row, claim=None, revision=row.revision + 1,
                      phase="uncertain" if row.started else row.phase)
    if mode == "submit":
        require(not row.quarantined, "restore_quarantine")
        require(row.phase == "ready" and not row.started and not row.cancel,
                "not_submit_ready")
        require(state.authorized, "claim_authority")
        require(row.request.due <= now < row.request.not_after,
                "submission_time")
        require(row.attempts < 3, "submission_budget")
    else:
        require(mode == "reconcile" and row.phase in {"ready", "waiting", "uncertain"},
                "not_reconcilable")
        # Read-only provider reconciliation remains permitted after revocation
        # or expiry; it cannot authorize another submission.
    handle = Claim(state.activation, execution, row.revision + 1, token,
                   now + 10, mode)
    next_state.executions[execution] = replace(
        row, revision=handle.revision, claim=handle,
        attempts=row.attempts + (mode == "submit"))
    return next_state, handle


def expire(state, execution, now):
    next_state = deepcopy(state)
    row = next_state.executions[execution]
    require(row.claim is not None and now >= row.claim.until, "lease_not_expired")
    next_state.executions[execution] = replace(
        row, claim=None, revision=row.revision + 1,
        phase="uncertain" if row.started else row.phase)
    return next_state


def live(state, handle, now):
    require(state.active and state.activation == handle.activation, "activation_fence")
    row = state.executions[handle.execution]
    require(row.claim == handle and row.revision == handle.revision, "claim_fence")
    require(now < handle.until, "lease_expired")
    return row


def start(state, handle, now):
    row = live(state, handle, now)
    require(handle.mode == "submit" and row.phase == "ready" and not row.started,
            "not_startable")
    require(state.authorized, "start_authority")
    require(not row.cancel and not row.quarantined, "start_suppressed")
    require(now < row.request.not_after, "submission_expired")
    next_state = deepcopy(state)
    next_state.executions[handle.execution] = replace(row, started=True)
    return next_state


class Provider:
    """Journal survives restoring the local State; accept() simulates HTTP I/O."""

    def __init__(self):
        self.accepted = {}
        self.calls = []

    def accept(self, started_snapshot, handle):
        # This is the worker's previously confirmed marker snapshot. A provider
        # cannot consult the current local lease, activation or cancellation.
        row = started_snapshot.executions[handle.execution]
        require(row.started and row.claim == handle and handle.mode == "submit",
                "start_not_committed")
        self.calls.append(handle.execution)
        # The chosen fake contract deduplicates indefinitely by execution key.
        old = self.accepted.setdefault(handle.execution, row.request)
        require(old == row.request, "provider_key_content_conflict")


def success(state, execution):
    next_state = deepcopy(state)
    row = next_state.executions[execution]
    require(row.phase not in {"failed", "cancelled"}, "terminal_fact_conflict")
    fact = (row.request.account, row.request.units)
    require(execution not in next_state.facts or next_state.facts[execution] == fact,
            "fact_conflict")
    next_state.facts[execution] = fact
    if row.phase != "succeeded":
        next_state.executions[execution] = replace(
            row, phase="succeeded", claim=None, revision=row.revision + 1,
            application="pending", quarantined=False)
    return next_state


def finish(state, handle, now):
    row = live(state, handle, now)
    require(row.started and handle.mode == "submit", "not_started_submission")
    return success(state, handle.execution)


def safe_retry(state, handle, now):
    """Only an adapter's definitive not-submitted fact permits this transition."""
    row = live(state, handle, now)
    require(row.started and handle.mode == "submit", "not_started_submission")
    next_state = deepcopy(state)
    next_state.executions[handle.execution] = replace(
        row, phase="ready", started=False, claim=None, revision=row.revision + 1)
    return next_state


def reconcile(state, handle, provider, now):
    row = live(state, handle, now)
    require(handle.mode == "reconcile", "not_reconciliation")
    if handle.execution in provider.accepted:
        return success(state, handle.execution)
    # Empty lookup is deliberately inconclusive, including a restored prestart
    # snapshot. No receipt found is not a proof of non-submission.
    next_state = deepcopy(state)
    next_state.executions[handle.execution] = replace(
        row, phase="uncertain", claim=None, revision=row.revision + 1,
        quarantined=False)
    return next_state


def apply(state, execution):
    row = state.executions[execution]
    require(execution in state.facts and row.phase == "succeeded", "no_success_fact")
    if row.application == "applied":
        return deepcopy(state)
    next_state = deepcopy(state)
    amount = next_state.facts[execution][1]
    # A rejected business application changes no domain values. The immutable
    # fact remains committed; a separate diagnostic records blocked status.
    if next_state.balance < amount:
        next_state.executions[execution] = replace(row, application="blocked")
    else:
        next_state.balance -= amount
        next_state.executions[execution] = replace(row, application="applied")
    return next_state


def cancel(state, execution):
    row = state.executions[execution]
    require(row.phase not in {"succeeded", "failed", "cancelled"}, "terminal_cancel")
    next_state = deepcopy(state)
    next_state.executions[execution] = replace(
        row, cancel=True, claim=None, revision=row.revision + 1,
        phase="uncertain" if row.started or row.phase == "waiting" else "cancelled")
    return next_state


def restore(snapshot, fresh_activation):
    next_state = deepcopy(snapshot)
    require(fresh_activation != snapshot.activation, "fresh_activation_required")
    next_state.active = False
    next_state.activation = fresh_activation
    for execution, row in next_state.executions.items():
        next_state.executions[execution] = replace(
            row, claim=None, revision=row.revision + 1,
            quarantined=unresolved(row))
    return next_state


def receipt(state, event, execution, body, verified=True, abort=False):
    require(verified, "signature")
    require(execution in state.executions, "unknown_execution")
    key = (state.executions[execution].request.account, event)
    value = (execution, hashlib.sha256(body).hexdigest())
    if key in state.inbox:
        require(state.inbox[key] == value, "event_content_conflict")
        return deepcopy(state), "ack"
    require(len(state.inbox) < 256, "inbox_limit")
    next_state = deepcopy(state)
    next_state.inbox[key] = value
    require(not abort, "inbox_storage_failure")
    return next_state, "ack"


def run():
    passed, rejected = [], []

    def check(name, condition):
        assert condition, name
        passed.append(name)

    def rejects(name, operation, reason):
        try:
            operation()
        except Rejected as error:
            assert str(error) == reason, (name, str(error), reason)
            rejected.append(name)
        else:
            raise AssertionError("accepted unsafe control: " + name)

    initial = State()
    rejects("atomic_intent_abort", lambda: submit(initial, "aborted", balance=12,
                                                 abort=True),
            "injected_abort_after_intent")
    check("aborted_snapshot_has_no_business_or_receipt_or_intent",
          initial == State())
    state, execution = submit(initial, "op", balance=12)
    replayed, same = submit(state, "op", balance=12)
    check("operation_replay_one_execution", replayed == state and same == execution)
    rejects("rebind_operation_content", lambda: submit(state, "op", Request(units=4)),
            "operation_content_conflict")
    provider = Provider()
    state, first = claim(state, execution, 0, "worker-1")
    rejects("duplicate_claim", lambda: claim(state, execution, 1, "worker-2"),
            "lease_live")
    rejects("provider_call_before_marker", lambda: provider.accept(state, first),
            "start_not_committed")
    revoked = replace(deepcopy(state), authorized=False)
    rejects("requester_revoked_before_start", lambda: start(revoked, first, 1),
            "start_authority")
    expired = expire(state, execution, 10)
    recovered, second = claim(expired, execution, 10, "worker-2")
    rejects("stale_claim_start", lambda: start(recovered, first, 11), "claim_fence")
    started = start(recovered, second, 11)
    provider.accept(started, second)
    uncertain = expire(started, execution, 20)
    check("expired_started_becomes_uncertain",
          uncertain.executions[execution].phase == "uncertain")
    rejects("resubmit_expired_started", lambda: claim(uncertain, execution, 20, "again"),
            "not_submit_ready")
    rejects("finish_after_lease_expiry", lambda: finish(started, second, 20),
            "lease_expired")
    uncertain.authorized = False
    uncertain, lookup = claim(uncertain, execution, 21, "lookup", "reconcile")
    confirmed = reconcile(uncertain, lookup, provider, 22)
    confirmed.balance = 2
    blocked = apply(confirmed, execution)
    check("success_fact_survives_rejected_application",
          blocked.balance == 2 and execution in blocked.facts
          and blocked.executions[execution].application == "blocked"
          and unresolved(blocked.executions[execution]))
    blocked.balance = 5
    applied = apply(blocked, execution)
    check("application_retry_exactly_once",
          applied.balance == 2 and apply(applied, execution) == applied)
    check("revocation_does_not_erase_started_provider_fact",
          not applied.authorized and len(provider.accepted) == 1)

    pending, another = submit(State(), "cancel-before")
    pending, cancel_handle = claim(pending, another, 0, "cancel-worker")
    cancelled = cancel(pending, another)
    rejects("cancel_before_start", lambda: start(cancelled, cancel_handle, 1),
            "claim_fence")
    cancelled_late = cancel(started, execution)
    check("cancel_after_start_retains_uncertainty",
          cancelled_late.executions[execution].phase == "uncertain"
          and cancelled_late.executions[execution].started)
    rejects("late_cancelled_worker_completion",
            lambda: finish(cancelled_late, second, 13), "claim_fence")
    paused_remote = Provider()
    paused_remote.accept(started, second)
    check("cancellation_cannot_fence_already_authorized_remote_call",
          execution in paused_remote.accepted
          and cancelled_late.executions[execution].phase == "uncertain")
    rejects("confirmed_event_cannot_regress_prestart_cancellation",
            lambda: success(cancelled, another), "terminal_fact_conflict")

    before_start, old_execution = submit(State(), "restore-op")
    live_state, old_handle = claim(before_start, old_execution, 0, "old-worker")
    live_state = start(live_state, old_handle, 1)
    remote = Provider()
    remote.accept(live_state, old_handle)
    restored = restore(before_start, 2)
    rejects("restored_dispatch_disabled",
            lambda: claim(restored, old_execution, 3, "new-worker"), "dispatch_disabled")
    restored.active = True  # Operator chooses reconciliation-only activation.
    rejects("prestart_snapshot_cannot_resubmit",
            lambda: claim(restored, old_execution, 3, "new-worker"), "restore_quarantine")
    rejects("old_activation_completion", lambda: finish(restored, old_handle, 3),
            "activation_fence")
    restored, restore_lookup = claim(restored, old_execution, 3, "restore-lookup", "reconcile")
    restored = reconcile(restored, restore_lookup, remote, 4)
    check("stale_backup_reconciles_without_remote_resend",
          len(remote.calls) == 1 and restored.executions[old_execution].phase == "succeeded")
    missing = restore(before_start, 3)
    missing.active = True
    missing, missing_lookup = claim(missing, old_execution, 4, "empty", "reconcile")
    missing = reconcile(missing, missing_lookup, Provider(), 5)
    check("empty_provider_lookup_stays_uncertain",
          missing.executions[old_execution].phase == "uncertain")
    rejects("empty_lookup_authorizes_no_resend",
            lambda: claim(missing, old_execution, 6, "unsafe"), "not_submit_ready")

    hook, hook_execution = submit(State(), "hook")
    rejects("unverified_webhook", lambda: receipt(hook, "event", hook_execution,
                                                b"delivered", verified=False), "signature")
    rejects("no_ack_on_inbox_failure", lambda: receipt(hook, "event", hook_execution,
                                                     b"delivered", abort=True),
            "inbox_storage_failure")
    check("failed_inbox_write_leaves_no_dedup_entry", hook.inbox == {})
    inbox, ack = receipt(hook, "event", hook_execution, b"delivered")
    duplicate, duplicate_ack = receipt(inbox, "event", hook_execution, b"delivered")
    check("durable_duplicate_ack", ack == duplicate_ack == "ack" and duplicate == inbox)
    rejects("event_id_conflicting_body", lambda: receipt(inbox, "event", hook_execution,
                                                       b"different"), "event_content_conflict")
    # Different operations can reuse the source identity; receipt correlation
    # retains the old execution and cannot complete the replacement.
    replacement, new_execution = submit(inbox, "replacement", Request(source="dispatch"))
    replacement = success(replacement, hook_execution)
    check("source_reuse_does_not_reuse_execution",
          new_execution != hook_execution
          and replacement.executions[new_execution].phase == "ready")
    rejects("claim_after_request_expiry", lambda: claim(hook, hook_execution, 100, "late"),
            "submission_time")
    near_expiry, expiry_handle = claim(hook, hook_execution, 95, "deadline")
    rejects("start_after_request_expiry", lambda: start(near_expiry, expiry_handle, 100),
            "submission_expired")
    denied = replace(deepcopy(hook), authorized=False)
    rejects("requester_revoked_before_claim", lambda: claim(denied, hook_execution, 0, "denied"),
            "claim_authority")
    retried, retry_execution = submit(State(), "safe-retry")
    for number in range(3):
        retried, retry_handle = claim(retried, retry_execution, number, f"retry-{number}")
        retried = start(retried, retry_handle, number)
        retried = safe_retry(retried, retry_handle, number)
    rejects("fourth_provider_submission_attempt",
            lambda: claim(retried, retry_execution, 4, "excess"), "submission_budget")

    full = State()
    for number in range(64):
        full, _ = submit(full, f"active-{number}")
    rejects("sixty_fifth_unresolved", lambda: submit(full, "overflow"), "unresolved_limit")
    replay_full, _ = submit(full, "active-0")
    check("replay_allowed_at_unresolved_cap", replay_full == full)
    retained = State()
    for number in range(256):
        retained, item = submit(retained, f"retained-{number}")
        retained = cancel(retained, item)
    rejects("two_hundred_fifty_seventh_retained", lambda: submit(retained, "overflow"),
            "retained_limit")

    return {
        "scope": "logical lifecycle oracle; no Rust, persistence, clock, HTTP or capacity evidence",
        "passed": passed,
        "rejected_controls": rejected,
        "counts": {"passed": len(passed), "rejected_controls": len(rejected)},
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
