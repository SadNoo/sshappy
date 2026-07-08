from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Iterator

import pymysql
from pymysql.cursors import DictCursor

from .keys import decode_psk, derive_user_key_b64, identity_hash
from .models import NodeInfo, RuntimeConfig, TrafficDelta, User


class Database:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    @contextmanager
    def connect(self) -> Iterator[pymysql.Connection]:
        conn = pymysql.connect(
            host=self.config.mysql_host,
            port=self.config.mysql_port,
            user=self.config.mysql_user,
            password=self.config.mysql_password,
            database=self.config.mysql_db,
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=False,
        )
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def load_node(self) -> NodeInfo:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, node_group, node_class, node_speedlimit, traffic_rate, sort,
                       server, node_bandwidth, node_bandwidth_limit
                FROM ss_node
                WHERE id = %s
                  AND (node_bandwidth < node_bandwidth_limit OR node_bandwidth_limit = 0)
                """,
                (self.config.node_id,),
            )
            row = cur.fetchone()
        if row is None:
            raise RuntimeError(f"node {self.config.node_id} not found or bandwidth-limited")
        if int(row["sort"]) != 14:
            raise RuntimeError(f"node {self.config.node_id} must be sort=14")
        host, port, server_key_b64 = parse_ss_single_port(str(row["server"]))
        return NodeInfo(
            id=int(row["id"]),
            group=int(row["node_group"]),
            node_class=int(row["node_class"]),
            speedlimit=float(row["node_speedlimit"] or 0),
            traffic_rate=float(row["traffic_rate"] or 1),
            sort=int(row["sort"]),
            server=str(row["server"]),
            listen_port=port,
            server_key_b64=server_key_b64,
            server_key=decode_psk(server_key_b64),
        )

    def load_users(self, node: NodeInfo) -> list[User]:
        conditions = [
            "enable = 1",
            "expire_in > NOW()",
            "transfer_enable > u + d",
        ]
        params: list[object] = []
        if node.group == 0:
            conditions.append("(class >= %s OR is_admin = 1)")
            params.append(node.node_class)
        else:
            conditions.append("((class >= %s AND node_group = %s) OR is_admin = 1)")
            params.extend([node.node_class, node.group])
        sql = f"""
            SELECT id, email, passwd, forbidden_ip, forbidden_port, disconnect_ip,
                   node_speedlimit
            FROM user
            WHERE {' AND '.join(conditions)}
        """
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        users: list[User] = []
        for row in rows:
            key_b64 = derive_user_key_b64(
                user_id=int(row["id"]),
                passwd=str(row["passwd"]),
                node_id=node.id,
                server_key_b64=node.server_key_b64,
            )
            key = decode_psk(key_b64)
            users.append(
                User(
                    id=int(row["id"]),
                    email=str(row["email"]),
                    passwd=str(row["passwd"]),
                    forbidden_ip=str(row["forbidden_ip"] or ""),
                    forbidden_port=str(row["forbidden_port"] or ""),
                    disconnect_ip=str(row["disconnect_ip"] or ""),
                    node_speedlimit=float(row["node_speedlimit"] or 0),
                    user_key_b64=key_b64,
                    user_key=key,
                    identity_hash=identity_hash(key),
                )
            )
        return users

    def report_traffic(self, node: NodeInfo, traffic: list[TrafficDelta]) -> None:
        if not traffic:
            return
        now = int(time.time())
        with self.connect() as conn, conn.cursor() as cur:
            for delta in traffic:
                billed_u = int(delta.upload * node.traffic_rate)
                billed_d = int(delta.download * node.traffic_rate)
                cur.execute(
                    "UPDATE user SET u = u + %s, d = d + %s, t = %s WHERE id = %s",
                    (billed_u, billed_d, now, delta.user_id),
                )
                cur.execute(
                    """
                    INSERT INTO user_traffic_log
                      (user_id, u, d, node_id, rate, traffic, log_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        delta.user_id,
                        delta.upload,
                        delta.download,
                        node.id,
                        node.traffic_rate,
                        flow_auto_show(int((delta.upload + delta.download) * node.traffic_rate)),
                        now,
                    ),
                )
            total = sum(item.upload + item.download for item in traffic)
            cur.execute(
                """
                UPDATE ss_node
                SET node_heartbeat = %s, node_bandwidth = node_bandwidth + %s
                WHERE id = %s
                """,
                (now, total, node.id),
            )

    def report_alive_ips(self, node: NodeInfo, alive_ips: dict[int, set[str]]) -> None:
        if not alive_ips:
            return
        now = int(time.time())
        with self.connect() as conn, conn.cursor() as cur:
            for user_id, ips in alive_ips.items():
                for ip in ips:
                    cur.execute(
                        "INSERT INTO alive_ip (nodeid, userid, ip, datetime) VALUES (%s, %s, %s, %s)",
                        (node.id, user_id, ip, now),
                    )

    def report_node_status(self, node: NodeInfo, online_users: int) -> None:
        now = int(time.time())
        uptime = int(time.monotonic())
        load = f"{os.getloadavg()[0]:.2f}" if hasattr(os, "getloadavg") else "0.00"
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ss_node_online_log (node_id, online_user, log_time) VALUES (%s, %s, %s)",
                (node.id, online_users, now),
            )
            cur.execute(
                "INSERT INTO ss_node_info (node_id, uptime, `load`, log_time) VALUES (%s, %s, %s, %s)",
                (node.id, uptime, load, now),
            )
            cur.execute(
                "UPDATE ss_node SET node_heartbeat = %s WHERE id = %s",
                (now, node.id),
            )


def parse_ss_single_port(value: str) -> tuple[str, int, str]:
    parts = value.split(";")
    host = parts[0] if parts else ""
    port = 443
    if len(parts) >= 2 and parts[1] not in ("", "0"):
        port = int(parts[1])
    server_key = parts[2] if len(parts) >= 3 else ""
    if not host:
        raise ValueError("ss_node.server host is empty")
    if not server_key:
        raise ValueError("ss_node.server server_key is empty")
    return host, port, server_key


def flow_auto_show(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.2f}{unit}"
        amount /= 1024
    return f"{amount:.2f}PB"
