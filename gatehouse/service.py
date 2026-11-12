"""Application service coordinating authentication, policy, quota, and audit."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .audit import AuditLog
from .models import AccessRequest, Decision, Policy, Session
from .policy import PolicyEngine
from .quota import QuotaLedger
from .session import SessionStore


class Gatehouse:
    def __init__(
        self,
        policies: Iterable[Policy] = (),
        sessions: Iterable[Session] = (),
        quota_limits: Mapping[str, int] | None = None,
    ) -> None:
        self.policies = PolicyEngine(policies)
        self.sessions = SessionStore(sessions)
        self.quotas = QuotaLedger(quota_limits)
        self.audit = AuditLog()

    def handle(self, request: AccessRequest) -> Decision:
        principal, session_error = self.sessions.resolve(
            request.session_token, request.now
        )
        if principal is None:
            decision = Decision(request.request_id, False, str(session_error))
            self.audit.append(decision)
            return decision

        allowed, reason, policy = self.policies.evaluate(principal, request)
        if allowed and not self.quotas.consume(principal, request.action):
            allowed, reason = False, "quota_exhausted"

        decision = Decision(request.request_id, allowed, reason, policy)
        self.audit.append(decision)
        return decision

    def handle_batch(
        self, requests: Iterable[AccessRequest], *, atomic: bool
    ) -> list[Decision]:
        quota_checkpoint = self.quotas.snapshot()
        audit_checkpoint = len(self.audit)
        decisions: list[Decision] = []
        for request in requests:
            decision = self.handle(request)
            decisions.append(decision)
            if atomic and not decision.allowed:
                self.quotas.restore(quota_checkpoint)
                self.audit.truncate(audit_checkpoint)
                return decisions
        return decisions

