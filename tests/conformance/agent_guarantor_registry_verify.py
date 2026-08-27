#!/usr/bin/env python3
"""Independent Guarantor V1 registry and deterministic-CBOR digest verifier."""

import hashlib
import json
import struct
import sys


def head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", value)


def cbor(value):
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and value >= 0:
        return head(0, value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        pairs = [(cbor(key), cbor(item)) for key, item in value.items()]
        pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return head(5, len(pairs)) + b"".join(key + item for key, item in pairs)
    raise ValueError("unsupported fixture value")


def digest(domain, value):
    raw_domain = domain.encode("ascii")
    framed = b"TOS-PROTOCOL-CBOR\x00" + struct.pack(">H", len(raw_domain)) + raw_domain + cbor(value)
    return "sha256:" + hashlib.sha256(framed).hexdigest()


def lp16(value):
    assert len(value) <= 0xFFFF
    return struct.pack(">H", len(value)) + value


def lp32(value):
    assert len(value) <= 0xFFFFFFFF
    return struct.pack(">I", len(value)) + value


def semantic_action_preimage(action_kind, fields):
    domain = ("tos.semantic-action." + action_kind + ".v1").encode("ascii")
    output = b"TOS-SAI\x00" + struct.pack(">HH", 1, 1)
    output += lp16(domain) + lp16(action_kind.encode("ascii"))
    output += struct.pack(">H", len(fields))
    for field in fields:
        output += lp16(field["name"].encode("ascii"))
        kind = field["type"]
        if kind == "digest32":
            assert field["text"].startswith("sha256:")
            value = bytes.fromhex(field["text"][7:])
            assert len(value) == 32
        elif kind == "u64":
            value = struct.pack(">Q", field["number"])
        else:
            assert kind in {"id", "kind", "state"}
            value = field["text"].encode("utf-8")
        output += lp32(value)
    return output


def require_registry(registry, expected_size, kind_field):
    assert registry["schema_version"] == 1 and registry["registry_version"] == 1
    assert len(registry["entries"]) == expected_size
    kinds = [entry[kind_field] for entry in registry["entries"]]
    assert len(kinds) == len(set(kinds)) if kind_field == "object_kind" else True


def main():
    document = json.load(sys.stdin)
    assert document["schema"] == "tos.service.agent-guarantor-conformance-fixture.v1"
    assert document["profile_uri"] == "tos.agent-service.guarantor.v1"
    assert document["commerce_profile_event_content_type"] == (
        "application/vnd.tos.service.commerce-profile-event.v1+cbor"
    )
    carriage = document["commerce_carriage_registry"]
    assert len(carriage) == 23
    assert len({entry["object_kind"] for entry in carriage}) == len(carriage)
    assert all(entry["content_type"].startswith("application/vnd.tos.service.agent-guarantor-")
               for entry in carriage)
    objects = document["object_registry"]
    mutations = document["mutation_registry"]
    require_registry(objects, 89, "object_kind")
    require_registry(mutations, 21, "operation_id")
    assert document["object_registry_digest"] == digest(
        "tos.service.agent-guarantor-object-verifier-registry.v1", objects
    )
    assert document["object_registry_canonical_cbor_hex"] == cbor(objects).hex()
    assert document["mutation_registry_digest"] == digest(
        "tos.service.agent-guarantor-mutation-verifier-registry.v1", mutations
    )
    assert document["mutation_registry_canonical_cbor_hex"] == cbor(mutations).hex()
    required_actions = {
        "commercial.quote.issue", "commercial.quote.close", "conditional.claim.ingress",
        "conditional.claim.submit", "conditional.claim-filing.close", "conditional.claim-decision.admit",
        "conditional.claim.decide", "conditional.claim.transition", "conditional.obligation.transition",
        "collateral.transition", "portfolio.release", "payment.direct", "payment.domain-bound",
        "settlement.external",
    }
    assert required_actions <= {entry["action_kind"] for entry in mutations["entries"]}
    vectors = document["coverage_state_vectors"]
    assert [item["name"] for item in vectors] == [
        "accepted-genesis", "activated", "filing-frozen-zero-claims"
    ]
    for item in vectors:
        assert item["canonical_cbor_hex"] == cbor(item["state"]).hex()
        assert item["digest"] == digest(
            "tos.service.agent-guarantor-coverage-state-vector.v1", item["state"]
        )
    assert vectors[0]["state"]["coverage_status"] == "pending_authorization"
    assert vectors[1]["state"]["coverage_status"] == "active"
    assert vectors[1]["state"]["claim_filing_status"] == "open"
    assert vectors[2]["state"]["claim_filing_status"] == "frozen"
    action_vectors = document["semantic_action_vectors"]
    assert [item["name"] for item in action_vectors] == ["guarantor-domain-bound-payout"]
    for item in action_vectors:
        preimage = semantic_action_preimage(item["action_kind"], item["fields"])
        assert item["preimage_hex"] == preimage.hex()
        assert item["stable_action_id"] == "sha256:" + hashlib.sha256(preimage).hexdigest()


if __name__ == "__main__":
    main()
