"""Immutable domain objects shared by the Gatehouse components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Principal:
    tenant: str
    actor: str
    roles: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.tenant or not self.actor:
            raise ValueError("tenant and actor must be non-empty")


@dataclass(frozen=True, slots=True)
class Session:
    token: str
    principal: Principal
    expires_at: int

    def __post_init__(self) -> None:
        if not self.token:
            raise ValueError("session token must be non-empty")
        if self.expires_at < 0:
            raise ValueError("expires_at cannot be negative")


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    tenant: str
    resource_prefix: str
    actions: frozenset[str]
    any_roles: frozenset[str]
    effect: Effect = Effect.ALLOW
    priority: int = 0

    def __post_init__(self) -> None:
        if not self.name or not self.tenant:
            raise ValueError("policy name and tenant must be non-empty")
        if not self.resource_prefix.startswith("/"):
            raise ValueError("resource_prefix must be absolute")
        if not self.actions:
            raise ValueError("a policy must contain at least one action")
        if self.effect is Effect.ALLOW and not self.any_roles:
            raise ValueError("allow policies must contain at least one role")


@dataclass(frozen=True, slots=True)
class AccessRequest:
    request_id: str
    session_token: str
    action: str
    resource: str
    now: int

    def __post_init__(self) -> None:
        if not self.request_id or not self.session_token or not self.action:
            raise ValueError("request_id, session_token, and action are required")
        if not self.resource.startswith("/"):
            raise ValueError("resource must be absolute")
        if self.now < 0:
            raise ValueError("now cannot be negative")


@dataclass(frozen=True, slots=True)
class Decision:
    request_id: str
    allowed: bool
    reason: str
    policy: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "policy": self.policy,
            "reason": self.reason,
            "request_id": self.request_id,
        }

