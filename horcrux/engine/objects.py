"""Object + identity binding core.

Ownership comes from actual evidence — never inferred from URL names.
A cross-identity authorization test is generated only when enough
evidence establishes the object boundary.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field


class ObjectInstance(BaseModel):
    object_type: str
    object_id: str
    source_endpoint: str = ""
    identifier_location: str = ""  # path|query|body|response
    identifier_field: str = "id"
    provenance: str = "unknown"
    observed_fields: list[str] = Field(default_factory=list)
    owner_identity_id: str = ""
    owner_evidence: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    @property
    def key(self) -> str:
        return f"{self.object_type}:{self.object_id}"

    @property
    def ownership_proven(self) -> bool:
        return bool(self.owner_identity_id and self.owner_evidence)


class IdentityContext(BaseModel):
    identity_id: str
    role: str = "anonymous"  # anonymous|user|privileged|admin
    authentication_state: str = "anonymous"
    session_reference: str = ""
    credential_reference: str = ""
    provenance: str = "unknown"
    available: bool = False


_COLLECTION_RE = re.compile(r"^/(?:api|rest|v\d+)/[A-Za-z_-]+/?$", re.I)
_INSTANCE_RE = re.compile(r"/(\d+|[{:][^/}]+[}:]|[0-9a-fA-F-]{36}|[0-9a-fA-F]{16,32})(?=/|$|\?|#)")


def is_collection_endpoint(path: str) -> bool:
    """A bare collection (/api/users) is never proof of object semantics."""
    return bool(_COLLECTION_RE.match((path or "").split("?")[0]))


def extract_instance_id(path: str) -> str:
    m = _INSTANCE_RE.search(path or "")
    return m.group(1) if m else ""


def collection_vs_instance(path: str) -> str:
    if extract_instance_id(path):
        return "instance"
    if is_collection_endpoint(path):
        return "collection"
    return "unknown"


def prove_ownership(instance: ObjectInstance, owner_id: str,
                    evidence: str) -> ObjectInstance:
    out = instance.model_copy(deep=True)
    out.owner_identity_id = owner_id
    if evidence not in out.owner_evidence:
        out.owner_evidence.append(evidence)
    return out


# Authorization test matrix: (actor, target-object) -> allowed?
# Only generated when ownership is proven AND both identities available.
MATRIX_ACTORS = ("anonymous", "identity_a", "identity_b", "privileged")
MATRIX_TARGETS = ("own_object", "other_object", "privileged_object",
                  "restricted_function", "collection", "mutation")


def authorization_tests_available(instance: ObjectInstance,
                                  identities: list[IdentityContext]) -> list[dict]:
    """Concrete cross-identity tests. Empty unless the object boundary is
    established by real evidence (proven owner + 2 available identities)."""
    if not instance.ownership_proven:
        return []
    avail = {i.identity_id for i in identities if i.available}
    if instance.owner_identity_id not in avail:
        return []
    others = [a for a in avail if a != instance.owner_identity_id]
    if not others:
        return []
    tests = []
    for other in sorted(others):
        tests.append({
            "actor": other,
            "target": instance.key,
            "kind": "cross_identity_read",
            "requires": ["object_instance", "owner_evidence", "second_identity"],
        })
    return tests
