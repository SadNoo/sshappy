from __future__ import annotations

import asyncio
import logging
import time

from .config import load_config
from .db import Database
from .server import SSServer
from .state import RuntimeState

logger = logging.getLogger(__name__)


class Service:
    def __init__(self) -> None:
        self.config = load_config()
        logging.basicConfig(
            level=getattr(logging, self.config.log_level, logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        if self.config.node_id <= 0:
            raise RuntimeError("node_id/NODE_ID must be set")
        self.db = Database(self.config)
        self.state = RuntimeState()
        self.server = SSServer(
            listen_host=self.config.listen_host,
            connect_timeout=self.config.tcp_connect_timeout,
            idle_timeout=self.config.tcp_idle_timeout,
            udp_idle_timeout=self.config.udp_idle_timeout,
            state=self.state,
        )
        self.node = None
        self.last_traffic_report = 0.0
        self.last_alive_report = 0.0
        self.last_node_report = 0.0

    async def run(self) -> None:
        await self.sync_once()
        server_task = asyncio.create_task(self.server.serve_forever())
        sync_task = asyncio.create_task(self.loop())
        await asyncio.gather(server_task, sync_task)

    async def loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.sync_interval_seconds)
            try:
                await self.sync_once()
            except Exception:
                logger.exception("sync cycle failed")

    async def sync_once(self) -> None:
        node = await asyncio.to_thread(self.db.load_node)
        users = await asyncio.to_thread(self.db.load_users, node)
        await self.server.apply(node, users)
        self.node = node
        now = time.monotonic()

        if now - self.last_traffic_report >= self.config.traffic_report_seconds:
            traffic = await self.state.snapshot_traffic()
            await asyncio.to_thread(self.db.report_traffic, node, traffic)
            self.last_traffic_report = now
            logger.info("traffic reported: users=%s", len(traffic))

        if now - self.last_node_report >= self.config.node_report_seconds:
            online = await self.state.online_user_count()
            await asyncio.to_thread(self.db.report_node_status, node, online)
            self.last_node_report = now
            logger.info("node status reported: online=%s", online)

        if now - self.last_alive_report >= self.config.alive_ip_report_seconds:
            alive = await self.state.snapshot_alive_ips()
            await asyncio.to_thread(self.db.report_alive_ips, node, alive)
            self.last_alive_report = now
            logger.info("alive ips reported: users=%s records=%s", len(alive), sum(len(v) for v in alive.values()))
