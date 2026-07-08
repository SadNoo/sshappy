from __future__ import annotations

import os

from .models import RuntimeConfig


def getenv(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def getenv_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    return int(value)


def load_config() -> RuntimeConfig:
    return RuntimeConfig(
        mysql_host=getenv("MYSQLHOST", getenv("MYSQL_HOST", "127.0.0.1")),
        mysql_port=getenv_int("MYSQLPORT", getenv_int("MYSQL_PORT", 3306)),
        mysql_db=getenv("MYSQLDBNAME", getenv("MYSQL_DB", "sspanel")),
        mysql_user=getenv("MYSQLUSR", getenv("MYSQL_USER", "root")),
        mysql_password=getenv("MYSQLPASSWD", getenv("MYSQL_PASS", "")),
        node_id=getenv_int("node_id", getenv_int("NODE_ID", 0)),
        listen_host=getenv("LISTEN_HOST", "0.0.0.0"),
        sync_interval_seconds=getenv_int("SYNC_INTERVAL_SECONDS", 60),
        traffic_report_seconds=getenv_int("TRAFFIC_REPORT_SECONDS", 60),
        node_report_seconds=getenv_int("NODE_REPORT_SECONDS", 60),
        alive_ip_report_seconds=getenv_int("ALIVE_IP_REPORT_SECONDS", 60),
        tcp_connect_timeout=getenv_int("TCP_CONNECT_TIMEOUT", 10),
        tcp_idle_timeout=getenv_int("TCP_IDLE_TIMEOUT", 300),
        udp_idle_timeout=getenv_int("UDP_IDLE_TIMEOUT", 300),
        log_level=getenv("LOG_LEVEL", "INFO").upper(),
    )
