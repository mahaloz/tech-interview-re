"""Policy selection and evaluation."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AccessRequest, Effect, Policy, Principal
from .paths import contains


class PolicyEngine:
    def __init__(self, policies: Iterable[Policy] = ()) -> None:
        self._policies = tuple(policies)

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    def evaluate(
        self, principal: Principal, request: AccessRequest
    ) -> tuple[bool, str, str | None]:
        candidates = [
            policy
            for policy in self._policies
            if policy.tenant == principal.tenant
            and request.action in policy.actions
            and contains(policy.resource_prefix, request.resource)
        ]
        candidates.sort(key=lambda policy: (-policy.priority, policy.name))

        for policy in candidates:
            if policy.effect is Effect.DENY:
                return False, "explicit_deny", policy.name
            if principal.roles & policy.any_roles:
                return True, "policy_allowed", policy.name
        if candidates:
            return False, "missing_role", candidates[0].name
        return False, "no_matching_policy", None

