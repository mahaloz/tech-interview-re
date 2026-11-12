from __future__ import annotations

import unittest

from gatehouse.audit import AuditLog
from gatehouse.models import AccessRequest, Decision, Effect, Policy, Principal, Session
from gatehouse.paths import canonical_path, contains
from gatehouse.service import Gatehouse


def request(request_id: str, token: str = "token-a", resource: str = "/docs/a") -> AccessRequest:
    return AccessRequest(request_id, token, "read", resource, 100)


class PathTests(unittest.TestCase):
    def test_canonical_path_removes_one_trailing_slash(self) -> None:
        self.assertEqual(canonical_path("/docs/"), "/docs")

    def test_contains_descendant(self) -> None:
        self.assertTrue(contains("/docs", "/docs/a"))

    def test_rejects_traversal(self) -> None:
        with self.assertRaises(ValueError):
            canonical_path("/docs/../secrets")


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alice = Principal("acme", "alice", frozenset({"reader", "employee"}))
        self.bob = Principal("acme", "bob", frozenset({"reader", "employee"}))
        self.policy = Policy(
            "docs",
            "acme",
            "/docs",
            frozenset({"read"}),
            frozenset({"reader", "employee"}),
        )
        self.sessions = [
            Session("token-a", self.alice, 1000),
            Session("token-b", self.bob, 1000),
        ]

    def service(self, limit: int = 3) -> Gatehouse:
        return Gatehouse([self.policy], self.sessions, {"read": limit})

    def test_allows_matching_request(self) -> None:
        decision = self.service().handle(request("r1"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.policy, "docs")

    def test_denies_unknown_session(self) -> None:
        decision = self.service().handle(request("r1", token="missing"))
        self.assertEqual(decision.reason, "unknown_session")

    def test_deny_policy_wins_by_priority(self) -> None:
        deny = Policy(
            "blocked",
            "acme",
            "/docs/private",
            frozenset({"read"}),
            frozenset(),
            Effect.DENY,
            priority=10,
        )
        service = Gatehouse([self.policy, deny], self.sessions)
        self.assertEqual(service.handle(request("r1", resource="/docs/private/x")).reason, "explicit_deny")

    def test_quota_exhaustion_for_one_user(self) -> None:
        service = self.service(limit=2)
        self.assertTrue(service.handle(request("r1")).allowed)
        self.assertTrue(service.handle(request("r2")).allowed)
        self.assertEqual(service.handle(request("r3")).reason, "quota_exhausted")

    def test_successful_atomic_batch(self) -> None:
        service = self.service(limit=2)
        decisions = service.handle_batch([request("r1"), request("r2")], atomic=True)
        self.assertTrue(all(item.allowed for item in decisions))
        self.assertEqual(len(service.audit), 2)

    def test_revocation(self) -> None:
        service = self.service()
        self.assertTrue(service.sessions.revoke("token-a"))
        self.assertEqual(service.handle(request("r1")).reason, "revoked_session")


class AuditTests(unittest.TestCase):
    def test_hash_chain_verifies(self) -> None:
        audit = AuditLog()
        audit.append(Decision("r1", True, "ok", "docs"))
        audit.append(Decision("r2", False, "denied"))
        self.assertTrue(audit.verify())


if __name__ == "__main__":
    unittest.main()
