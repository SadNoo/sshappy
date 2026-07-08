import asyncio
import base64
import socket
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sshappy.crypto import aes_ecb_decrypt_block
from sshappy.keys import derive_session_subkey
from sshappy.models import NodeInfo, TargetAddress
from sshappy.server import SSServer
from sshappy.state import RuntimeState

from test_udp_protocol import make_client_packet, make_user


class EchoProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


def test_udp_server_echo_round_trip():
    asyncio.run(run_udp_server_echo_round_trip())


async def run_udp_server_echo_round_trip():
    loop = asyncio.get_running_loop()
    echo_transport, _ = await loop.create_datagram_endpoint(
        EchoProtocol,
        local_addr=("127.0.0.1", 0),
    )
    echo_port = echo_transport.get_extra_info("sockname")[1]

    server_key = bytes(range(32))
    user_key = bytes(reversed(range(32)))
    user = make_user(user_key)
    server_port = get_free_udp_port()
    server = SSServer(
        listen_host="127.0.0.1",
        connect_timeout=2,
        idle_timeout=10,
        udp_idle_timeout=10,
        state=RuntimeState(),
    )
    node = NodeInfo(
        id=14,
        group=0,
        node_class=0,
        speedlimit=0,
        traffic_rate=1,
        sort=14,
        server=f"127.0.0.1;{server_port};{base64.b64encode(server_key).decode('ascii')}",
        listen_port=server_port,
        server_key_b64=base64.b64encode(server_key).decode("ascii"),
        server_key=server_key,
    )
    await server.apply(node, [user])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        payload = b"ping-over-udp"
        packet = make_client_packet(
            server_key,
            user_key,
            session_id=11,
            packet_id=12,
            target=TargetAddress("127.0.0.1", echo_port),
            payload=payload,
        )
        await loop.sock_sendto(sock, packet, ("127.0.0.1", server_port))
        response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), timeout=3)
        assert decrypt_server_response(user_key, response).endswith(payload)

        traffic = await server.state.snapshot_traffic()
        assert len(traffic) == 1
        assert traffic[0].user_id == user.id
        assert traffic[0].upload == len(payload)
        assert traffic[0].download == len(payload)
    finally:
        sock.close()
        echo_transport.close()
        if server._udp_transport is not None:
            server._udp_transport.close()
        if server._server is not None:
            server._server.close()
            await server._server.wait_closed()
        await server.close_udp_associations()


def decrypt_server_response(user_key: bytes, packet: bytes) -> bytes:
    header = aes_ecb_decrypt_block(user_key, packet[:16])
    server_session_id = struct.unpack("!Q", header[:8])[0]
    return AESGCM(derive_session_subkey(user_key, struct.pack("!Q", server_session_id))).decrypt(
        header[4:16],
        packet[16:],
        None,
    )


def get_free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()
