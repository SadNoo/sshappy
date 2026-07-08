from __future__ import annotations

import asyncio
from collections import defaultdict

from .models import TrafficDelta


class RuntimeState:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._traffic: dict[int, TrafficDelta] = {}
        self._alive_ips: dict[int, set[str]] = defaultdict(set)

    async def add_traffic(self, user_id: int, upload: int = 0, download: int = 0) -> None:
        async with self._lock:
            delta = self._traffic.setdefault(user_id, TrafficDelta(user_id=user_id))
            delta.upload += upload
            delta.download += download

    async def add_alive_ip(self, user_id: int, ip: str) -> None:
        async with self._lock:
            self._alive_ips[user_id].add(ip)

    async def snapshot_traffic(self) -> list[TrafficDelta]:
        async with self._lock:
            rows = list(self._traffic.values())
            self._traffic = {}
            return rows

    async def snapshot_alive_ips(self) -> dict[int, set[str]]:
        async with self._lock:
            rows = {uid: set(ips) for uid, ips in self._alive_ips.items()}
            self._alive_ips = defaultdict(set)
            return rows

    async def online_user_count(self) -> int:
        async with self._lock:
            return len(self._alive_ips)

