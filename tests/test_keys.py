import base64

from sshappy.keys import decode_psk, derive_user_key_b64, identity_hash


def test_derive_user_key_matches_panel_shape():
    server_key = base64.b64encode(bytes(range(32))).decode("ascii")
    user_key = derive_user_key_b64(123, "passwd", 14, server_key)
    assert len(decode_psk(user_key)) == 32


def test_identity_hash_is_16_bytes():
    key = bytes(range(32))
    assert len(identity_hash(key)) == 16

