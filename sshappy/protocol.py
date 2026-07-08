from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    AesGcmStream,
    aes_ecb_decrypt_block,
    aes_ecb_encrypt_block,
    encrypted_len,
    pack_length,
    unpack_length,
)
from .keys import derive_identity_subkey, derive_session_subkey, same_key
from .models import IDENTITY_HEADER_LEN, SALT_LEN, TAG_LEN, TCP_MAX_PAYLOAD_SIZE, TargetAddress, User


class ProtocolError(Exception):
    pass


UDP_HEADER_LEN = 16
UDP_CLIENT_TYPE = 0
UDP_SERVER_TYPE = 1
UDP_TIMESTAMP_MAX_DIFF = 30


@dataclass
class ClientRequest:
    user: User
    target: TargetAddress
    initial_payload: bytes
    decryptor: AesGcmStream
    request_salt: bytes


@dataclass
class UdpClientPacket:
    user: User
    target: TargetAddress
    payload: bytes
    client_session_id: int
    packet_id: int


async def read_exact(reader: asyncio.StreamReader, size: int) -> bytes:
    try:
        return await reader.readexactly(size)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("connection closed before full header was received") from exc


async def read_client_request(
    reader: asyncio.StreamReader,
    users_by_identity: dict[bytes, User],
    server_key: bytes,
    max_time_diff: int = 30,
) -> ClientRequest:
    salt = await read_exact(reader, SALT_LEN)
    identity_header = await read_exact(reader, IDENTITY_HEADER_LEN)
    identity_subkey = derive_identity_subkey(server_key, salt)
    identity_plain = aes_ecb_decrypt_block(identity_subkey, identity_header)
    user = users_by_identity.get(identity_plain)
    if user is None:
        raise ProtocolError("unknown SS2022 identity")

    decryptor = AesGcmStream(derive_session_subkey(user.user_key, salt))
    fixed_header = decryptor.decrypt(await read_exact(reader, encrypted_len(11)))
    if len(fixed_header) != 11:
        raise ProtocolError("invalid fixed header length")
    header_type = fixed_header[0]
    timestamp = struct.unpack("!Q", fixed_header[1:9])[0]
    variable_len = struct.unpack("!H", fixed_header[9:11])[0]

    if header_type != 0:
        raise ProtocolError("invalid client header type")
    if abs(int(time.time()) - int(timestamp)) > max_time_diff:
        raise ProtocolError("request timestamp outside allowed window")
    if variable_len <= 0 or variable_len > TCP_MAX_PAYLOAD_SIZE:
        raise ProtocolError("invalid variable header length")

    variable_header = decryptor.decrypt(await read_exact(reader, encrypted_len(variable_len)))
    target, payload, padding_len = parse_client_variable_header(variable_header)
    if not payload and padding_len == 0:
        raise ProtocolError("request header has no payload or padding")
    return ClientRequest(
        user=user,
        target=target,
        initial_payload=payload,
        decryptor=decryptor,
        request_salt=salt,
    )


def parse_client_variable_header(data: bytes) -> tuple[TargetAddress, bytes, int]:
    target, offset = parse_target_address(data, 0)
    if len(data) < offset + 2:
        raise ProtocolError("short port or padding length")
    padding_len = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    if len(data) < offset + padding_len:
        raise ProtocolError("short padding")
    offset += padding_len
    return target, data[offset:], padding_len


def parse_target_address(data: bytes, offset: int = 0) -> tuple[TargetAddress, int]:
    if len(data) < offset + 1:
        raise ProtocolError("empty address header")
    atyp = data[offset]
    offset += 1

    if atyp == 1:
        if len(data) < offset + 4:
            raise ProtocolError("short ipv4 address")
        host = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
    elif atyp == 3:
        if len(data) < offset + 1:
            raise ProtocolError("short domain length")
        domain_len = data[offset]
        offset += 1
        if len(data) < offset + domain_len:
            raise ProtocolError("short domain address")
        host = data[offset : offset + domain_len].decode("idna")
        offset += domain_len
    elif atyp == 4:
        if len(data) < offset + 16:
            raise ProtocolError("short ipv6 address")
        host = str(ipaddress.IPv6Address(data[offset : offset + 16]))
        offset += 16
    else:
        raise ProtocolError("unsupported address type")

    if len(data) < offset + 2:
        raise ProtocolError("short port")
    port = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    return TargetAddress(host=host, port=port), offset


def pack_target_address(target: TargetAddress) -> bytes:
    try:
        ip = ipaddress.ip_address(target.host)
    except ValueError:
        host = target.host.encode("idna")
        if len(host) > 255:
            raise ProtocolError("domain name is too long")
        return b"\x03" + bytes([len(host)]) + host + struct.pack("!H", target.port)

    if isinstance(ip, ipaddress.IPv4Address):
        return b"\x01" + ip.packed + struct.pack("!H", target.port)
    return b"\x04" + ip.packed + struct.pack("!H", target.port)


async def read_client_payload(reader: asyncio.StreamReader, decryptor: AesGcmStream) -> bytes:
    encrypted_length = await read_exact(reader, encrypted_len(2))
    length = unpack_length(decryptor.decrypt(encrypted_length))
    if length > TCP_MAX_PAYLOAD_SIZE:
        raise ProtocolError("payload chunk too large")
    if length == 0:
        return b""
    return decryptor.decrypt(await read_exact(reader, encrypted_len(length)))


async def write_response_header_and_payload(
    writer: asyncio.StreamWriter,
    user_key: bytes,
    request_salt: bytes,
    payload: bytes,
) -> AesGcmStream:
    response_salt = os.urandom(SALT_LEN)
    encryptor = AesGcmStream(derive_session_subkey(user_key, response_salt))
    fixed_header = (
        b"\x01"
        + struct.pack("!Q", int(time.time()))
        + request_salt
        + pack_length(len(payload))
    )
    writer.write(response_salt)
    writer.write(encryptor.encrypt(fixed_header))
    writer.write(encryptor.encrypt(payload))
    await writer.drain()
    return encryptor


async def write_response_payload(writer: asyncio.StreamWriter, encryptor: AesGcmStream, payload: bytes) -> None:
    writer.write(encryptor.encrypt(pack_length(len(payload))))
    writer.write(encryptor.encrypt(payload))
    await writer.drain()


def decrypt_udp_client_packet(
    packet: bytes,
    users_by_identity: dict[bytes, User],
    server_key: bytes,
    max_time_diff: int = UDP_TIMESTAMP_MAX_DIFF,
) -> UdpClientPacket:
    min_len = UDP_HEADER_LEN + IDENTITY_HEADER_LEN + TAG_LEN + 1 + 8 + 2
    if len(packet) < min_len:
        raise ProtocolError("udp packet too short")

    header = aes_ecb_decrypt_block(server_key, packet[:UDP_HEADER_LEN])
    session_id = struct.unpack("!Q", header[:8])[0]
    packet_id = struct.unpack("!Q", header[8:16])[0]

    eih_plain = aes_ecb_decrypt_block(server_key, packet[UDP_HEADER_LEN : UDP_HEADER_LEN + IDENTITY_HEADER_LEN])
    identity = bytes(left ^ right for left, right in zip(eih_plain, header))
    user = users_by_identity.get(identity)
    if user is None:
        raise ProtocolError("unknown SS2022 udp identity")

    encrypted = packet[UDP_HEADER_LEN + IDENTITY_HEADER_LEN :]
    nonce = header[4:16]
    plaintext = AESGCM(derive_session_subkey(user.user_key, struct.pack("!Q", session_id))).decrypt(
        nonce,
        encrypted,
        None,
    )
    if len(plaintext) < 1 + 8 + 2:
        raise ProtocolError("udp plaintext too short")

    offset = 0
    socket_type = plaintext[offset]
    offset += 1
    if socket_type != UDP_CLIENT_TYPE:
        raise ProtocolError("invalid udp client packet type")

    timestamp = struct.unpack("!Q", plaintext[offset : offset + 8])[0]
    offset += 8
    if abs(int(time.time()) - int(timestamp)) > max_time_diff:
        raise ProtocolError("udp packet timestamp outside allowed window")

    padding_len = struct.unpack("!H", plaintext[offset : offset + 2])[0]
    offset += 2
    if len(plaintext) < offset + padding_len:
        raise ProtocolError("short udp padding")
    offset += padding_len

    target, offset = parse_target_address(plaintext, offset)
    return UdpClientPacket(
        user=user,
        target=target,
        payload=plaintext[offset:],
        client_session_id=session_id,
        packet_id=packet_id,
    )


def encrypt_udp_server_packet(
    user: User,
    target: TargetAddress,
    payload: bytes,
    client_session_id: int,
    packet_id: int,
    server_session_id: int,
) -> bytes:
    header = struct.pack("!QQ", server_session_id, packet_id)
    plaintext = (
        bytes([UDP_SERVER_TYPE])
        + struct.pack("!Q", int(time.time()))
        + struct.pack("!Q", client_session_id)
        + b"\x00\x00"
        + pack_target_address(target)
        + payload
    )
    nonce = header[4:16]
    encrypted = AESGCM(derive_session_subkey(user.user_key, struct.pack("!Q", server_session_id))).encrypt(
        nonce,
        plaintext,
        None,
    )
    return aes_ecb_encrypt_block(user.user_key, header) + encrypted


def make_udp_server_session_id() -> int:
    return secrets.randbits(64)


def is_forbidden_port(user: User, port: int) -> bool:
    for rule in split_rules(user.forbidden_port):
        if "-" in rule or ":" in rule:
            sep = "-" if "-" in rule else ":"
            left, right = rule.split(sep, 1)
            if left.isdigit() and right.isdigit() and int(left) <= port <= int(right):
                return True
        elif rule.isdigit() and int(rule) == port:
            return True
    return False


def is_forbidden_host(user: User, host: str) -> bool:
    rules = split_rules(user.forbidden_ip)
    if not rules:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for rule in rules:
        try:
            if "/" in rule and ip in ipaddress.ip_network(rule, strict=False):
                return True
            if "/" not in rule and same_key(ip.packed, ipaddress.ip_address(rule).packed):
                return True
        except ValueError:
            continue
    return False


def is_disconnect_ip(user: User, client_ip: str) -> bool:
    return client_ip in split_rules(user.disconnect_ip)


def split_rules(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]
