"""Resource path validation and matching."""

from __future__ import annotations


def canonical_path(value: str) -> str:
    """Return a canonical absolute resource path.

    Gatehouse paths are identifiers, not filesystem paths. Empty components and
    traversal-like components are rejected instead of silently normalized.
    """

    if not value.startswith("/"):
        raise ValueError("resource path must be absolute")
    if value != "/" and value.endswith("/"):
        value = value[:-1]
    pieces = value.split("/")[1:]
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise ValueError("resource path contains an invalid component")
    return "/" if not pieces else "/" + "/".join(pieces)


def contains(prefix: str, resource: str) -> bool:
    """Whether *resource* is *prefix* itself or one of its descendants."""

    clean_prefix = canonical_path(prefix)
    clean_resource = canonical_path(resource)
    if clean_prefix == "/":
        return True
    return clean_resource.startswith(clean_prefix)

