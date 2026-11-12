"""Conversion between JSON-shaped data and domain objects."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import AccessRequest, Effect, Policy, Principal, Session
from .paths import canonical_path


def _required(data: Mapping[str, Any], name: str, expected: type) -> Any:
    value = data.get(name)
    if not isinstance(value, expected):
        raise ValueError(f"{name} must be {expected.__name__}")
    return value


def _string_list(data: Mapping[str, Any], name: str) -> list[str]:
    value = data.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return value


def decode_principal(data: Mapping[str, Any]) -> Principal:
    roles = _string_list(data, "roles") if "roles" in data else []
    return Principal(
        tenant=_required(data, "tenant", str),
        actor=_required(data, "actor", str),
        roles=frozenset(roles),
    )


def decode_session(data: Mapping[str, Any]) -> Session:
    principal = data.get("principal")
    if not isinstance(principal, dict):
        raise ValueError("principal must be an object")
    return Session(
        token=_required(data, "token", str),
        principal=decode_principal(principal),
        expires_at=_required(data, "expires_at", int),
    )


def decode_policy(data: Mapping[str, Any]) -> Policy:
    actions = _string_list(data, "actions")
    roles = _string_list(data, "any_roles")
    try:
        effect = Effect(data.get("effect", "allow"))
    except ValueError as exc:
        raise ValueError("effect must be allow or deny") from exc
    return Policy(
        name=_required(data, "name", str),
        tenant=_required(data, "tenant", str),
        resource_prefix=canonical_path(_required(data, "resource_prefix", str)),
        actions=frozenset(actions),
        any_roles=frozenset(roles),
        effect=effect,
        priority=data.get("priority", 0),
    )


def decode_request(data: Mapping[str, Any]) -> AccessRequest:
    return AccessRequest(
        request_id=_required(data, "request_id", str),
        session_token=_required(data, "session_token", str),
        action=_required(data, "action", str),
        resource=canonical_path(_required(data, "resource", str)),
        now=_required(data, "now", int),
    )

