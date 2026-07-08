import base64

from sshappy.db import parse_ss_single_port


def test_parse_ss_single_port_defaults():
    key = base64.b64encode(bytes(range(32))).decode("ascii")
    host, port, server_key = parse_ss_single_port(f"example.com;;{key}")
    assert host == "example.com"
    assert port == 443
    assert server_key == key


def test_parse_ss_single_port_custom_port():
    key = base64.b64encode(bytes(range(32))).decode("ascii")
    host, port, server_key = parse_ss_single_port(f"example.com;23336;{key}")
    assert host == "example.com"
    assert port == 23336
    assert server_key == key

