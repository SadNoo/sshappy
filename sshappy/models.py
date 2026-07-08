from __future__ import annotations

from dataclasses import dataclass


METHOD = "2022-blake3-aes-256-gcm"
KEY_LEN = 32
SALT_LEN = 32
TAG_LEN = 16
IDENTITY_HEADER_LEN = 16
TCP_MAX_PAYLOAD_SIZE = 0xFFFF


@dataclass(frozen=True)
class RuntimeConfig:
    mysql_host: str
    mysql_port: int
    mysql_db: str
    mysql_user: str
    mysql_password: str
    node_id: int
    listen_host: str
    sync_interval_seconds: int
    traffic_report_seconds: int
    node_report_seconds: int
    alive_ip_report_seconds: int
    tcp_connect_timeout: int
    tcp_idle_timeout: int
    log_level: str


@dataclass(frozen=True)
class NodeInfo:
    id: int
    group: int
    node_class: int
    speedlimit: float
    traffic_rate: float
    sort: int
    server: str
    listen_port: int
    server_key_b64: str
    server_key: bytes


@dataclass(frozen=True)
class User:
    id: int
    email: str
    passwd: str
    forbidden_ip: str
    forbidden_port: str
    disconnect_ip: str
    node_speedlimit: float
    user_key_b64: str
    user_key: bytes
    identity_hash: bytes


@dataclass(frozen=True)
class TargetAddress:
    host: str
    port: int


@dataclass
class TrafficDelta:
    user_id: int
    upload: int = 0
    download: int = 0
