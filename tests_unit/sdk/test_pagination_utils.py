import pytest

from cerebro_sdk.pagination import encode_cursor, decode_cursor, Cursor


def test_encode_decode_cursor_roundtrip():
    payload = {"offset": 25, "org_id": "1234"}
    token = encode_cursor(payload)
    decoded = decode_cursor(token)
    assert isinstance(decoded, Cursor)
    assert decoded.payload == {"offset": 25, "org_id": "1234"}


def test_decode_cursor_invalid_payload_raises():
    garbage = encode_cursor([1, 2, 3])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        decode_cursor(garbage)
