#!/usr/bin/env python3
"""Stateless JSON-RPC calls and explicit, durable mutation plans. Python 3.11+."""

import argparse
import http.client
import json
import os
from pathlib import Path
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_REQUEST_BYTES = 65536
MAX_PLAN_BYTES = 131072
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
PLAN_FORMAT = "rebase-operation-plan-1"


class ClientError(Exception):
    def __init__(self, kind, message):
        self.kind = kind
        super().__init__(message)


class RpcError(ClientError):
    """A complete error response, including explicit unknown commit outcomes."""


def _reject(message):
    raise ClientError("invalid_plan", message)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("Duplicate JSON object key")
        result[key] = value
    return result


def loads(data):
    try:
        return json.loads(data, object_pairs_hook=_object,
                          parse_constant=lambda _: _reject("Nonfinite JSON number"))
    except (ValueError, RecursionError) as error:
        raise ClientError("invalid_json", "Invalid JSON input") from error


def _bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ClientError("invalid_json", "Value cannot be encoded as JSON") from error


def read_json(path):
    with open(path, "rb") as source:
        data = source.read(MAX_PLAN_BYTES + 1)
    if len(data) > MAX_PLAN_BYTES:
        _reject("JSON file exceeds the client file limit")
    return loads(data)


def endpoint(url):
    """Normalize the endpoint used to fence saved operations."""
    try:
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment):
            raise ValueError()
        port = parts.port
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        if port is not None and port != (443 if parts.scheme == "https" else 80):
            host += f":{port}"
        return urllib.parse.urlunsplit((parts.scheme, host, parts.path or "/rpc", "", ""))
    except (ValueError, TypeError) as error:
        raise ClientError("invalid_endpoint", "An HTTP(S) endpoint without credentials, query or fragment is required") from error


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(url, token, method, params, *, timeout=20):
    """Make one bounded call. Never retry, redirect, cache authority or log tokens."""
    url = endpoint(url)
    if not isinstance(method, str) or not method or not isinstance(params, dict):
        _reject("A method name and object params are required")
    if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise ClientError("invalid_token", "A bounded bearer token without whitespace is required")
    if not 0 < timeout <= 300:
        raise ClientError("invalid_timeout", "Timeout must be in (0, 300] seconds")
    request_id = str(uuid.uuid4())
    data = _bytes({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
    if len(data) > MAX_REQUEST_BYTES:
        raise ClientError("request_limit", "Request exceeds 65536 bytes")
    request = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        try:
            response = urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            expected_length = response.headers.get("Content-Length")
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if 300 <= status < 400:
            raise ClientError("redirect_rejected", "RPC redirects are not followed")
        if status == 401:
            raise ClientError("unauthenticated", "Credential rejected")
        if status == 429:
            raise ClientError("busy", "Server admission is full; no automatic retry")
        if len(body) > MAX_RESPONSE_BYTES:
            raise ClientError("outcome_unknown", "Response exceeds the client limit; retain any saved mutation plan")
        if expected_length is not None and (not expected_length.isdigit() or int(expected_length) != len(body)):
            raise ClientError("outcome_unknown", "Incomplete response; retain any saved mutation plan")
        try:
            value = loads(body)
        except ClientError as error:
            raise ClientError("outcome_unknown", "Response was not valid JSON; retain any saved mutation plan") from error
        if (not isinstance(value, dict) or value.get("jsonrpc") != "2.0"
                or value.get("id") != request_id
                or ("result" in value) == ("error" in value)):
            raise ClientError("outcome_unknown", "Invalid RPC response; retain any saved mutation plan")
        if "error" in value:
            error = value["error"]
            if not isinstance(error, dict) or not isinstance(error.get("data"), dict):
                raise ClientError("outcome_unknown", "Invalid RPC error response")
            kind = error["data"].get("kind")
            message = error.get("message")
            if not isinstance(kind, str) or not isinstance(message, str):
                raise ClientError("outcome_unknown", "Invalid RPC error response")
            raise RpcError(kind, message)
        if status != 200:
            raise ClientError("outcome_unknown", f"Unexpected HTTP status {status}; retain any saved mutation plan")
        return value["result"]
    except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
        # The peer may have committed even if connect/read/close failed locally.
        raise ClientError("outcome_unknown", "No complete response; reconcile or replay the original saved plan") from error


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError as error:
        raise ClientError("invalid_plan", "Canonical UUID required") from error
    return value


def _draft(draft):
    if (not isinstance(draft, dict) or not {"model", "commands", "returning"} <= draft.keys()
            or draft.keys() - {"model", "commands", "returning", "fixture"}
            or not isinstance(draft["model"], str) or not draft["model"]
            or not isinstance(draft["commands"], list) or not 1 <= len(draft["commands"]) <= 64
            or not isinstance(draft["returning"], list) or len(draft["returning"]) > 32):
        _reject("A draft requires model, 1-64 commands and up to 32 returning IDs; fixture metadata is optional")
    for identity in draft["returning"]:
        _uuid(identity)
    if len(set(draft["returning"])) != len(draft["returning"]):
        _reject("Duplicate returning ID")


def prepare(url, token, draft, *, operation_id=None, timeout=20):
    """Bind a new intended mutation once. This does not submit its commands."""
    _draft(draft)
    operation_id = _uuid(operation_id or str(uuid.uuid4()))
    url = endpoint(url)
    session = call(url, token, "session.describe", {}, timeout=timeout)
    if session["model"] != draft["model"]:
        raise ClientError("model_mismatch", "Draft and server model differ")
    plan = {"format": PLAN_FORMAT,
            "target": {key: session[key] for key in ("model", "store", "tenant", "actor")},
            "request": {"model": draft["model"], "context": session["operation_context"],
                        "operation_id": operation_id, "commands": draft["commands"],
                        "returning": draft["returning"]}}
    plan["target"]["url"] = url
    if "fixture" in draft:
        plan["fixture"] = draft["fixture"]
    # Detach the artifact from the caller's mutable draft.
    plan = loads(_bytes(plan))
    _plan(plan)
    return plan


def _plan(plan):
    if (not isinstance(plan, dict) or plan.get("format") != PLAN_FORMAT
            or not {"format", "target", "request"} <= plan.keys()
            or plan.keys() - {"format", "target", "request", "fixture"}):
        _reject("Unsupported saved plan")
    target, request = plan["target"], plan["request"]
    if not isinstance(target, dict) or target.keys() != {"url", "model", "store", "tenant", "actor"}:
        _reject("Invalid plan target")
    if not isinstance(request, dict) or request.keys() != {"model", "context", "operation_id", "commands", "returning"}:
        _reject("Invalid saved mutation")
    if target["url"] != endpoint(target["url"]) or target["model"] != request["model"]:
        _reject("Inconsistent plan target")
    for key in ("store", "tenant", "actor"):
        _uuid(target[key])
    _uuid(request["operation_id"])
    if not isinstance(request["context"], str) or not request["context"]:
        _reject("Original operation context is required")
    _draft({key: request[key] for key in ("model", "commands", "returning")})
    envelope = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "records.mutate", "params": request}
    if len(_bytes(envelope)) > MAX_REQUEST_BYTES:
        _reject("Saved mutation exceeds the request byte limit")


def save_plan(path, plan):
    """Durably publish a private plan without overwriting any existing path."""
    _plan(plan)
    data = _bytes(plan) + b"\n"
    if len(data) > MAX_PLAN_BYTES:
        _reject("Plan exceeds the file limit")
    destination = Path(path)
    # A hard link publishes the fully written file atomically and without clobber.
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".rebase-plan-") as temporary:
        temporary.write(data)
        temporary.flush()
        os.fsync(temporary.fileno())
        os.link(temporary.name, destination)
        if os.name == "posix":
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def execute(url, token, plan, *, status=False, timeout=20):
    """Submit or reconcile the exact saved intent; never replace its context."""
    _plan(plan)
    if endpoint(url) != plan["target"]["url"]:
        raise ClientError("target_mismatch", "Plan belongs to a different endpoint")
    current = call(url, token, "session.describe", {}, timeout=timeout)
    if any(current.get(key) != plan["target"][key] for key in ("model", "store", "tenant", "actor")):
        raise ClientError("target_mismatch", "Plan belongs to a different model, store, tenant or actor")
    request = plan["request"]
    if status:
        request = {key: request[key] for key in ("model", "context", "operation_id")}
    return call(url, token, "operations.status" if status else "records.mutate", request, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="HTTP(S) RPC endpoint")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=20)
    sub = parser.add_subparsers(dest="command", required=True)
    generic = sub.add_parser("call", help="one ordinary operation; no retries")
    generic.add_argument("method")
    generic.add_argument("params", nargs="?", help="JSON params file; defaults to {}")
    bind = sub.add_parser("prepare", help="bind and save a NEW intended operation before submission")
    bind.add_argument("draft")
    bind.add_argument("destination")
    bind.add_argument("--operation-id")
    for name in ("apply", "status"):
        sub.add_parser(name).add_argument("plan")
    args = parser.parse_args()
    with args.token_file.open() as source:
        token = source.read(16385).strip()
    if args.command == "call":
        result = call(args.url, token, args.method, read_json(args.params) if args.params else {}, timeout=args.timeout)
    elif args.command == "prepare":
        plan = prepare(args.url, token, read_json(args.draft), operation_id=args.operation_id, timeout=args.timeout)
        save_plan(args.destination, plan)
        result = {"status": "prepared", "plan": str(args.destination),
                  "operation_id": plan["request"]["operation_id"], "target": plan["target"]}
    else:
        result = execute(args.url, token, read_json(args.plan), status=args.command == "status", timeout=args.timeout)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (ClientError, OSError) as error:
        import sys
        print(json.dumps({"error": {"kind": getattr(error, "kind", "io"), "message": str(error)}}), file=sys.stderr)
        sys.exit(1)
