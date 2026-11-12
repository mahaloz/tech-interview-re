"""In-memory session state."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Principal, Session


class SessionStore:
    def __init__(self, sessions: Iterable[Session] = ()) -> None:
        self._sessions = {session.token: session for session in sessions}
        self._revoked: set[str] = set()

    def revoke(self, token: str) -> bool:
        if token not in self._sessions:
            return False
        self._revoked.add(token)
        return True

    def resolve(self, token: str, now: int) -> tuple[Principal | None, str | None]:
        session = self._sessions.get(token)
        if session is None:
            return None, "unknown_session"
        if token in self._revoked:
            return None, "revoked_session"
        if now >= session.expires_at:
            return None, "expired_session"
        return session.principal, None

