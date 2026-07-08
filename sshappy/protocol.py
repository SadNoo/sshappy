from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from .crypto import AesGcmStream, aes_ecb_decrypt_block, encrypted_len, pack_length, unpack_length
from .keys import derive_identity_subkey, derive_session_subkey, same_key
from .models import IDENTITY_HEADER_LEN, SALT_LEN, TCP_MAX_PAYLOAD_SIZE, TargetAddress, User


class ProtocolError(Exception):
    pass


@dataclass
class ClientRequest:
    user: User
    target: TargetAddress
    initial_payload: bytes
    decryptor: AesGcmStream
    request_salt: bytes


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
    if len(data) < 1:
        raise ProtocolError("empty variable header")
    offset = 0
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

    if len(data) < offset + 4:
        raise ProtocolError("short port or padding length")
    port = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    padding_len = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    if len(data) < offset + padding_len:
        raise ProtocolError("short padding")
    offset += padding_len
    return TargetAddress(host=host, port=port), data[offset:], padding_len


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
