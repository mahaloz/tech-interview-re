"""Stateful request quotas."""

from __future__ import annotations

from collections.abc import Mapping

from .models import Principal

QuotaKey = tuple[str, str]


def _key(principal: Principal, action: str) -> QuotaKey:
    return principal.tenant, action


class QuotaLedger:
    def __init__(self, limits: Mapping[str, int] | None = None) -> None:
        self._limits = dict(limits or {})
        if any(limit < 1 for limit in self._limits.values()):
            raise ValueError("quota limits must be positive")
        self._counts: dict[QuotaKey, int] = {}

    def consume(self, principal: Principal, action: str) -> bool:
        limit = self._limits.get(action)
        if limit is None:
            return True
        key = _key(principal, action)
        used = self._counts.get(key, 0)
        if used >= limit:
            return False
        self._counts[key] = used + 1
        return True

    def snapshot(self) -> dict[QuotaKey, int]:
        return self._counts

    def restore(self, snapshot: Mapping[QuotaKey, int]) -> None:
        self._counts = dict(snapshot)

    def usage(self, principal: Principal, action: str) -> int:
        return self._counts.get(_key(principal, action), 0)

