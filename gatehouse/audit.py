"""Append-only, hash-chained decision log."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from .models import Decision


def _digest(previous: str, payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{previous}:{encoded}".encode()).hexdigest()


def _payload(entry: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in entry.items() if key != "digest"}


def _valid_link(previous: str, entry: Mapping[str, object]) -> bool:
    return entry.get("digest") == _digest(previous, _payload(entry))


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[dict[str, object]] = []

    @property
    def entries(self) -> Sequence[Mapping[str, object]]:
        return tuple(dict(entry) for entry in self._entries)

    def append(self, decision: Decision) -> None:
        previous = str(self._entries[-1]["digest"]) if self._entries else "0" * 64
        payload = decision.to_dict()
        self._entries.append({**payload, "digest": _digest(previous, payload)})

    def truncate(self, length: int) -> None:
        if length < 0 or length > len(self._entries):
            raise ValueError("invalid audit checkpoint")
        del self._entries[length:]

    def __len__(self) -> int:
        return len(self._entries)

    def verify(self) -> bool:
        previous = "0" * 64
        for entry in self._entries:
            if not _valid_link(previous, entry):
                return False
            previous = str(entry["digest"])
        return True

