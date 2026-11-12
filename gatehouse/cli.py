"""Deterministic scenario runner used by humans and differential tools."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any, TextIO

from .codec import decode_policy, decode_request, decode_session
from .service import Gatehouse


def run_scenario(raw: Mapping[str, Any]) -> dict[str, object]:
    policies = raw.get("policies", [])
    sessions = raw.get("sessions", [])
    operations = raw.get("operations", [])
    limits = raw.get("quota_limits", {})
    if not all(isinstance(value, list) for value in (policies, sessions, operations)):
        raise ValueError("policies, sessions, and operations must be lists")
    if not isinstance(limits, dict):
        raise ValueError("quota_limits must be an object")

    service = Gatehouse(
        policies=(decode_policy(value) for value in policies),
        sessions=(decode_session(value) for value in sessions),
        quota_limits=limits,
    )
    results: list[dict[str, object]] = []
    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("operation must be an object")
        kind = operation.get("op")
        if kind == "request":
            request = operation.get("request")
            if not isinstance(request, dict):
                raise ValueError("request operation requires a request object")
            results.append({"op": "request", "decision": service.handle(decode_request(request)).to_dict()})
        elif kind == "batch":
            requests = operation.get("requests")
            if not isinstance(requests, list):
                raise ValueError("batch operation requires requests")
            decisions = service.handle_batch(
                (decode_request(value) for value in requests),
                atomic=bool(operation.get("atomic", False)),
            )
            results.append({"op": "batch", "decisions": [item.to_dict() for item in decisions]})
        elif kind == "revoke":
            token = operation.get("token")
            if not isinstance(token, str):
                raise ValueError("revoke operation requires a token")
            results.append({"op": "revoke", "revoked": service.sessions.revoke(token)})
        else:
            raise ValueError(f"unknown operation: {kind!r}")

    return {
        "audit": list(service.audit.entries),
        "audit_valid": service.audit.verify(),
        "results": results,
    }


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    source = stdin or sys.stdin
    destination = stdout or sys.stdout
    try:
        raw = json.load(source)
        if not isinstance(raw, dict):
            raise ValueError("scenario must be an object")
        result = run_scenario(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        json.dump({"error": str(exc)}, destination, sort_keys=True)
        destination.write("\n")
        return 2
    json.dump(result, destination, sort_keys=True, separators=(",", ":"))
    destination.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

