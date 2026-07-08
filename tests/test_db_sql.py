from pathlib import Path


def test_node_info_load_column_is_quoted():
    db_py = Path(__file__).resolve().parents[1] / "sshappy" / "db.py"
    source = db_py.read_text()
    assert "ss_node_info (node_id, uptime, `load`, log_time)" in source
    assert "ss_node_info (node_id, uptime, load, log_time)" not in source
