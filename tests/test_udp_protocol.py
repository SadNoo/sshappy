import base64
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sshappy.crypto import aes_ecb_decrypt_block, aes_ecb_encrypt_block
from sshappy.keys import derive_session_subkey, identity_hash
from sshappy.models import TargetAddress, User
from sshappy.protocol import (
    decrypt_udp_client_packet,
    encrypt_udp_server_packet,
    pack_target_address,
    parse_target_address,
)


def test_udp_client_packet_identifies_user_and_payload():
    server_key = bytes(range(32))
    user_key = bytes(reversed(range(32)))
    user = make_user(user_key)
    session_id = 0x0102030405060708
    packet_id = 9
    target = TargetAddress("8.8.8.8", 53)
    payload = b"\x12\x34dns"

    packet = make_client_packet(server_key, user_key, session_id, packet_id, target, payload)
    decoded = decrypt_udp_client_packet(packet, {user.identity_hash: user}, server_key)

    assert decoded.user.id == user.id
    assert decoded.target == target
    assert decoded.payload == payload
    assert decoded.client_session_id == session_id
    assert decoded.packet_id == packet_id


def test_udp_server_packet_round_trips():
    user_key = bytes(reversed(range(32)))
    user = make_user(user_key)
    target = TargetAddress("1.1.1.1", 53)
    payload = b"\xab\xcdreply"

    packet = encrypt_udp_server_packet(
        user=user,
        target=target,
        payload=payload,
        client_session_id=3,
        packet_id=4,
        server_session_id=5,
    )
    header = aes_ecb_decrypt_block(user_key, packet[:16])
    plaintext = AESGCM(derive_session_subkey(user_key, struct.pack("!Q", 5))).decrypt(
        header[4:16],
        packet[16:],
        None,
    )

    assert plaintext[0] == 1
    assert struct.unpack("!Q", plaintext[9:17])[0] == 3
    assert plaintext[17:19] == b"\x00\x00"
    decoded_target, offset = parse_target_address(plaintext, 19)
    assert decoded_target == target
    assert plaintext[offset:] == payload


def make_user(user_key: bytes) -> User:
    return User(
        id=7,
        email="u@example.test",
        passwd="passwd",
        forbidden_ip="",
        forbidden_port="",
        disconnect_ip="",
        node_speedlimit=0,
        user_key_b64=base64.b64encode(user_key).decode("ascii"),
        user_key=user_key,
        identity_hash=identity_hash(user_key),
    )


def make_client_packet(
    server_key: bytes,
    user_key: bytes,
    session_id: int,
    packet_id: int,
    target: TargetAddress,
    payload: bytes,
) -> bytes:
    header = struct.pack("!QQ", session_id, packet_id)
    identity_plain = bytes(left ^ right for left, right in zip(identity_hash(user_key), header))
    plaintext = (
        b"\x00"
        + struct.pack("!Q", int(time.time()))
        + b"\x00\x00"
        + pack_target_address(target)
        + payload
    )
    encrypted = AESGCM(derive_session_subkey(user_key, struct.pack("!Q", session_id))).encrypt(
        header[4:16],
        plaintext,
        None,
    )
    return aes_ecb_encrypt_block(server_key, header) + aes_ecb_encrypt_block(server_key, identity_plain) + encrypted
