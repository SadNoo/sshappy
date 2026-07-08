from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag

from .models import NodeInfo, TCP_MAX_PAYLOAD_SIZE, UDP_MAX_PACKET_SIZE, TargetAddress, User
from .protocol import (
    ProtocolError,
    decrypt_udp_client_packet,
    encrypt_udp_server_packet,
    is_disconnect_ip,
    is_forbidden_host,
    is_forbidden_port,
    make_udp_server_session_id,
    read_client_payload,
    read_client_request,
    write_response_header_and_payload,
    write_response_payload,
)
from .state import RuntimeState

logger = logging.getLogger(__name__)


@dataclass
class UserRegistry:
    node: NodeInfo | None = None
    users_by_identity: dict[bytes, User] = field(default_factory=dict)


@dataclass
class UdpAssociation:
    target: TargetAddress
    user: User
    client_addr: tuple[str, int]
    client_session_id: int
    server_session_id: int
    transport: asyncio.DatagramTransport
    packet_id: int
    last_seen: float


class SSServer:
    def __init__(
        self,
        listen_host: str,
        connect_timeout: int,
        idle_timeout: int,
        udp_idle_timeout: int,
        state: RuntimeState,
    ) -> None:
        self.listen_host = listen_host
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.state = state
        self.registry = UserRegistry()
        self._seen_salts: dict[bytes, float] = {}
        self._server: asyncio.AbstractServer | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._port: int | None = None
        self._udp_associations: dict[tuple[Any, ...], UdpAssociation] = {}

    async def apply(self, node: NodeInfo, users: list[User]) -> None:
        self.registry = UserRegistry(
            node=node,
            users_by_identity={user.identity_hash: user for user in users},
        )
        if self._server is None or self._port != node.listen_port:
            await self.restart(node.listen_port)
        logger.info("runtime users applied: node=%s port=%s users=%s", node.id, node.listen_port, len(users))

    async def restart(self, port: int) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
            await self.close_udp_associations()
        self._server = await asyncio.start_server(self.handle_client, self.listen_host, port)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: InboundUdpProtocol(self),
            local_addr=(self.listen_host, port),
        )
        self._udp_transport = transport
        self._port = port
        logger.info("SS2022 TCP server listening on %s:%s", self.listen_host, port)
        logger.info("SS2022 UDP server listening on %s:%s", self.listen_host, port)

    async def serve_forever(self) -> None:
        while self._server is None:
            await asyncio.sleep(0.1)
        while True:
            await asyncio.sleep(3600)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else ""
        node = self.registry.node
        if node is None:
            writer.close()
            await writer.wait_closed()
            return

        remote_writer: asyncio.StreamWriter | None = None
        try:
            request = await asyncio.wait_for(
                read_client_request(reader, self.registry.users_by_identity, node.server_key),
                timeout=self.connect_timeout,
            )
            user = request.user
            if self.is_replay(request.request_salt):
                raise ProtocolError("replayed salt")
            if is_disconnect_ip(user, client_ip):
                raise ProtocolError("client ip is in disconnect_ip")
            if is_forbidden_port(user, request.target.port) or is_forbidden_host(user, request.target.host):
                raise ProtocolError("target blocked by user rule")

            await self.state.add_alive_ip(user.id, client_ip)
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(request.target.host, request.target.port),
                timeout=self.connect_timeout,
            )
            if request.initial_payload:
                remote_writer.write(request.initial_payload)
                await remote_writer.drain()
                await self.state.add_traffic(user.id, upload=len(request.initial_payload))

            await self.relay_bidirectional(request, reader, writer, remote_reader, remote_writer, client_ip)
        except (ProtocolError, InvalidTag, OSError, asyncio.TimeoutError) as exc:
            logger.debug("connection closed from %s: %s", client_ip, exc)
        finally:
            if remote_writer is not None:
                remote_writer.close()
                await wait_closed(remote_writer)
            writer.close()
            await wait_closed(writer)

    async def relay_bidirectional(
        self,
        request,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        client_ip: str,
    ) -> None:
        user = request.user
        await self.state.add_alive_ip(user.id, client_ip)
        encryptor = None

        async def uplink() -> None:
            while True:
                payload = await asyncio.wait_for(
                    read_client_payload(client_reader, request.decryptor),
                    timeout=self.idle_timeout,
                )
                if payload == b"":
                    return
                remote_writer.write(payload)
                await remote_writer.drain()
                await self.state.add_traffic(user.id, upload=len(payload))
                await self.state.add_alive_ip(user.id, client_ip)

        async def downlink() -> None:
            nonlocal encryptor
            while True:
                payload = await asyncio.wait_for(remote_reader.read(TCP_MAX_PAYLOAD_SIZE), timeout=self.idle_timeout)
                if not payload:
                    return
                if encryptor is None:
                    encryptor = await write_response_header_and_payload(
                        client_writer,
                        user.user_key,
                        request.request_salt,
                        payload,
                    )
                else:
                    await write_response_payload(client_writer, encryptor, payload)
                await self.state.add_traffic(user.id, download=len(payload))
                await self.state.add_alive_ip(user.id, client_ip)

        tasks = [asyncio.create_task(uplink()), asyncio.create_task(downlink())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()

    def is_replay(self, salt: bytes) -> bool:
        now = time.monotonic()
        expired = [item for item, seen_at in self._seen_salts.items() if now - seen_at > 60]
        for item in expired:
            self._seen_salts.pop(item, None)
        if salt in self._seen_salts:
            return True
        self._seen_salts[salt] = now
        return False

    async def handle_udp_datagram(self, data: bytes, client_addr: tuple[str, int]) -> None:
        node = self.registry.node
        transport = self._udp_transport
        if node is None or transport is None:
            return

        client_ip = client_addr[0]
        try:
            packet = decrypt_udp_client_packet(data, self.registry.users_by_identity, node.server_key)
            user = packet.user
            if is_disconnect_ip(user, client_ip):
                raise ProtocolError("client ip is in disconnect_ip")
            if is_forbidden_port(user, packet.target.port) or is_forbidden_host(user, packet.target.host):
                raise ProtocolError("target blocked by user rule")

            await self.state.add_alive_ip(user.id, client_ip)
            await self.state.add_traffic(user.id, upload=len(packet.payload))
            assoc = await self.get_udp_association(
                user=user,
                target=packet.target,
                client_addr=client_addr,
                client_session_id=packet.client_session_id,
                packet_id=packet.packet_id,
            )
            assoc.transport.sendto(packet.payload)
        except (ProtocolError, InvalidTag, OSError, asyncio.TimeoutError) as exc:
            logger.debug("udp packet dropped from %s: %s", client_ip, exc)
        finally:
            self.cleanup_udp_associations()

    async def get_udp_association(
        self,
        user: User,
        target: TargetAddress,
        client_addr: tuple[str, int],
        client_session_id: int,
        packet_id: int,
    ) -> UdpAssociation:
        key = (client_addr, user.id, client_session_id, target.host, target.port)
        now = time.monotonic()
        assoc = self._udp_associations.get(key)
        if assoc is not None:
            assoc.packet_id = packet_id
            assoc.last_seen = now
            return assoc

        loop = asyncio.get_running_loop()
        remote_addr = (target.host, target.port)
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: OutboundUdpProtocol(self, key),
                remote_addr=remote_addr,
                family=socket.AF_UNSPEC,
            ),
            timeout=self.connect_timeout,
        )
        assoc = UdpAssociation(
            target=target,
            user=user,
            client_addr=client_addr,
            client_session_id=client_session_id,
            server_session_id=make_udp_server_session_id(),
            transport=transport,
            packet_id=packet_id,
            last_seen=now,
        )
        self._udp_associations[key] = assoc
        return assoc

    async def handle_udp_response(self, key: tuple[Any, ...], payload: bytes) -> None:
        assoc = self._udp_associations.get(key)
        transport = self._udp_transport
        if assoc is None or transport is None:
            return
        assoc.last_seen = time.monotonic()
        response = encrypt_udp_server_packet(
            user=assoc.user,
            target=assoc.target,
            payload=payload,
            client_session_id=assoc.client_session_id,
            packet_id=assoc.packet_id,
            server_session_id=assoc.server_session_id,
        )
        transport.sendto(response, assoc.client_addr)
        await self.state.add_traffic(assoc.user.id, download=len(payload))
        await self.state.add_alive_ip(assoc.user.id, assoc.client_addr[0])

    def cleanup_udp_associations(self) -> None:
        now = time.monotonic()
        expired = [key for key, assoc in self._udp_associations.items() if now - assoc.last_seen > self.udp_idle_timeout]
        for key in expired:
            assoc = self._udp_associations.pop(key, None)
            if assoc is not None:
                assoc.transport.close()

    async def close_udp_associations(self) -> None:
        for assoc in self._udp_associations.values():
            assoc.transport.close()
        self._udp_associations = {}


class InboundUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: SSServer) -> None:
        self.server = server

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > UDP_MAX_PACKET_SIZE:
            return
        asyncio.create_task(self.server.handle_udp_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.debug("inbound udp socket error: %s", exc)


class OutboundUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: SSServer, key: tuple[Any, ...]) -> None:
        self.server = server
        self.key = key

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > UDP_MAX_PACKET_SIZE:
            return
        asyncio.create_task(self.server.handle_udp_response(self.key, data))

    def error_received(self, exc: Exception) -> None:
        logger.debug("outbound udp socket error: %s", exc)


async def wait_closed(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.wait_closed()
    except Exception:
        pass
