from __future__ import annotations

import base64
import hashlib
from hmac import compare_digest

from blake3 import blake3

from .models import KEY_LEN, METHOD


IDENTITY_SUBKEY_CONTEXT = "shadowsocks 2022 identity subkey"
SESSION_SUBKEY_CONTEXT = "shadowsocks 2022 session subkey"


def decode_psk(value: str) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != KEY_LEN:
        raise ValueError("2022-blake3-aes-256-gcm key must decode to 32 bytes")
    return raw


def derive_user_key_b64(user_id: int, passwd: str, node_id: int, server_key_b64: str) -> str:
    material = "|".join([str(user_id), passwd, METHOD, str(node_id), server_key_b64])
    return base64.b64encode(hashlib.sha256(material.encode("utf-8")).digest()).decode("ascii")


def identity_hash(user_key: bytes) -> bytes:
    return blake3(user_key).digest(length=16)


def derive_identity_subkey(server_key: bytes, salt: bytes) -> bytes:
    return derive_key(IDENTITY_SUBKEY_CONTEXT, server_key + salt)


def derive_session_subkey(psk: bytes, salt: bytes) -> bytes:
    return derive_key(SESSION_SUBKEY_CONTEXT, psk + salt)


def derive_key(context: str, material: bytes) -> bytes:
    hasher = blake3(derive_key_context=context)
    hasher.update(material)
    return hasher.digest(length=32)


def same_key(left: bytes, right: bytes) -> bool:
    return compare_digest(left, right)
