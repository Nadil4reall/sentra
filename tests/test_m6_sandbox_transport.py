from __future__ import annotations

import json
import struct

import pytest
from pydantic import ValidationError

from src.controller.sandbox_context import PasswdSourceState, SandboxContextManifest
from src.controller.sandbox_transport import (
    SENTRA_VALIDATION_CHANNEL_NAME,
    SandboxContextAcknowledgement,
    SandboxContextRejectionCode,
    SandboxTransportError,
    decode_sandbox_acknowledgement_frame,
    decode_sandbox_context_frame,
    encode_sandbox_acknowledgement_frame,
    encode_sandbox_context_frame,
)


_HEADER_BYTES = 4
_MAX_PAYLOAD_BYTES = 4096


def _manifest() -> SandboxContextManifest:
    return SandboxContextManifest(
        context_version="1",
        control_id="7.1.1",
        source_state=PasswdSourceState(
            passwd_file_mode="0666",
            passwd_file_owner_uid=42,
            passwd_file_group_gid=43,
        ),
    )


def _frame_payload(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def _json_frame(payload: object) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _frame_payload(encoded)


def _manifest_payload() -> dict[str, object]:
    return {
        "context_version": "1",
        "control_id": "7.1.1",
        "source_state": {
            "passwd_file_mode": "0666",
            "passwd_file_owner_uid": 42,
            "passwd_file_group_gid": 43,
        },
    }


def test_manifest_frame_round_trip() -> None:
    manifest = _manifest()

    decoded = decode_sandbox_context_frame(encode_sandbox_context_frame(manifest))
    assert decoded == manifest


def test_manifest_serialization_is_deterministic() -> None:
    manifest = _manifest()

    assert encode_sandbox_context_frame(manifest) == encode_sandbox_context_frame(
        manifest
    )


def test_only_fixed_channel_name_is_exposed() -> None:
    assert SENTRA_VALIDATION_CHANNEL_NAME == "org.sentra.validation.0"


def test_frame_length_prefix_matches_utf8_payload_length() -> None:
    frame = encode_sandbox_context_frame(_manifest())

    assert struct.unpack("!I", frame[:_HEADER_BYTES])[0] == len(frame[_HEADER_BYTES:])
    assert len(frame[_HEADER_BYTES:]) <= _MAX_PAYLOAD_BYTES


def test_zero_length_frame_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="zero-length"):
        decode_sandbox_context_frame(struct.pack("!I", 0))


def test_oversized_frame_is_rejected_before_payload_is_present() -> None:
    oversized_header_only = struct.pack("!I", _MAX_PAYLOAD_BYTES + 1)

    with pytest.raises(SandboxTransportError, match="size limit"):
        decode_sandbox_context_frame(oversized_header_only)


def test_truncated_frame_header_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="header"):
        decode_sandbox_context_frame(b"\x00\x00")


def test_truncated_frame_payload_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="payload"):
        decode_sandbox_context_frame(struct.pack("!I", 10) + b"{}")


def test_trailing_frame_bytes_are_rejected() -> None:
    frame = encode_sandbox_context_frame(_manifest()) + b"x"

    with pytest.raises(SandboxTransportError, match="trailing"):
        decode_sandbox_context_frame(frame)


def test_invalid_utf8_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="UTF-8"):
        decode_sandbox_context_frame(_frame_payload(b"\xff"))


def test_invalid_json_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="valid JSON"):
        decode_sandbox_context_frame(_frame_payload(b"{not-json}"))


def test_json_array_is_rejected() -> None:
    with pytest.raises(SandboxTransportError, match="must be an object"):
        decode_sandbox_context_frame(_frame_payload(b"[]"))


def test_extra_top_level_field_is_rejected() -> None:
    payload = _manifest_payload()
    payload["hostname"] = "not-allowed"

    with pytest.raises(SandboxTransportError, match="supported schema"):
        decode_sandbox_context_frame(_json_frame(payload))


def test_extra_source_state_field_is_rejected() -> None:
    payload = _manifest_payload()
    source_state = payload["source_state"]
    assert isinstance(source_state, dict)
    source_state["path"] = "/etc/passwd"

    with pytest.raises(SandboxTransportError, match="supported schema"):
        decode_sandbox_context_frame(_json_frame(payload))


@pytest.mark.parametrize(
    "mutation",
    [
        {"context_version": "2"},
        {"control_id": "5.1.20"},
        {"source_state": {"passwd_file_mode": "064x"}},
        {"source_state": {"passwd_file_owner_uid": "0"}},
        {"source_state": {"passwd_file_group_gid": "0"}},
        {"source_state": {"passwd_file_owner_uid": True}},
        {"source_state": {"passwd_file_group_gid": True}},
        {"source_state": {"passwd_file_owner_uid": -1}},
        {"source_state": {"passwd_file_group_gid": -1}},
    ],
)
def test_invalid_manifest_schema_values_are_rejected(
    mutation: dict[str, object],
) -> None:
    payload = _manifest_payload()
    for key, value in mutation.items():
        if key == "source_state":
            source_state = payload["source_state"]
            assert isinstance(source_state, dict)
            assert isinstance(value, dict)
            source_state.update(value)
        else:
            payload[key] = value

    with pytest.raises(SandboxTransportError, match="supported schema"):
        decode_sandbox_context_frame(_json_frame(payload))


def test_duplicate_json_object_keys_are_rejected() -> None:
    duplicate = (
        b'{"context_version":"1","context_version":"1",'
        b'"control_id":"7.1.1","source_state":{}}'
    )

    with pytest.raises(SandboxTransportError, match="valid JSON"):
        decode_sandbox_context_frame(_frame_payload(duplicate))


def test_nonstandard_json_constant_is_rejected() -> None:
    invalid = (
        b'{"context_version":"1","control_id":"7.1.1",'
        b'"source_state":{"passwd_file_mode":"0644",'
        b'"passwd_file_owner_uid":NaN,"passwd_file_group_gid":0}}'
    )

    with pytest.raises(SandboxTransportError, match="valid JSON"):
        decode_sandbox_context_frame(_frame_payload(invalid))


def test_noncanonical_json_is_rejected() -> None:
    noncanonical = json.dumps(_manifest_payload(), indent=2).encode("utf-8")

    with pytest.raises(SandboxTransportError, match="canonical"):
        decode_sandbox_context_frame(_frame_payload(noncanonical))


def test_accepted_acknowledgement_round_trip() -> None:
    acknowledgement = SandboxContextAcknowledgement(
        protocol_version="1",
        status="accepted",
    )

    assert (
        decode_sandbox_acknowledgement_frame(
            encode_sandbox_acknowledgement_frame(acknowledgement)
        )
        == acknowledgement
    )


def test_rejected_acknowledgement_round_trip() -> None:
    acknowledgement = SandboxContextAcknowledgement(
        protocol_version="1",
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )

    assert (
        decode_sandbox_acknowledgement_frame(
            encode_sandbox_acknowledgement_frame(acknowledgement)
        )
        == acknowledgement
    )


def test_arbitrary_acknowledgement_status_is_rejected() -> None:
    payload = {"protocol_version": "1", "status": "maybe"}

    with pytest.raises(SandboxTransportError, match="protocol"):
        decode_sandbox_acknowledgement_frame(_json_frame(payload))


def test_arbitrary_acknowledgement_rejection_code_is_rejected() -> None:
    payload = {
        "protocol_version": "1",
        "status": "rejected",
        "reason_code": "host=/private/path",
    }

    with pytest.raises(SandboxTransportError, match="protocol"):
        decode_sandbox_acknowledgement_frame(_json_frame(payload))


def test_acknowledgement_extra_field_is_rejected() -> None:
    payload = {
        "protocol_version": "1",
        "status": "accepted",
        "message": "sensitive arbitrary text",
    }

    with pytest.raises(SandboxTransportError, match="protocol"):
        decode_sandbox_acknowledgement_frame(_json_frame(payload))


def test_acknowledgement_never_echoes_manifest() -> None:
    manifest = _manifest()
    acknowledgement = SandboxContextAcknowledgement(
        protocol_version="1",
        status="rejected",
        reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
    )
    ack_frame = encode_sandbox_acknowledgement_frame(acknowledgement)
    ack_payload = ack_frame[_HEADER_BYTES:]

    assert b"0666" not in ack_payload
    assert b"passwd_file_mode" not in ack_payload
    assert ack_payload == (
        b'{"protocol_version":"1","reason_code":"invalid_context",'
        b'"status":"rejected"}'
    )
    assert manifest.source_state.passwd_file_mode == "0666"


def test_protocol_models_are_immutable() -> None:
    manifest = _manifest()
    acknowledgement = SandboxContextAcknowledgement(
        protocol_version="1",
        status="accepted",
    )

    with pytest.raises(ValidationError):
        manifest.context_version = "2"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        acknowledgement.status = "rejected"  # type: ignore[misc]


def test_caller_cannot_select_another_channel_name() -> None:
    with pytest.raises(TypeError):
        encode_sandbox_context_frame(  # type: ignore[call-arg]
            _manifest(), channel_name="other"
        )


def test_encoder_rejects_mapping_instead_of_manifest_model() -> None:
    with pytest.raises(TypeError, match="SandboxContextManifest"):
        encode_sandbox_context_frame(_manifest_payload())  # type: ignore[arg-type]


def test_acknowledgement_rejects_reason_for_accepted_status() -> None:
    with pytest.raises(ValidationError):
        SandboxContextAcknowledgement(
            protocol_version="1",
            status="accepted",
            reason_code=SandboxContextRejectionCode.INVALID_CONTEXT,
        )


def test_acknowledgement_requires_reason_for_rejected_status() -> None:
    with pytest.raises(ValidationError):
        SandboxContextAcknowledgement(
            protocol_version="1",
            status="rejected",
        )
