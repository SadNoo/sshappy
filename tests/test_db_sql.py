import inspect

from sshappy.db import Database


def test_node_info_load_column_is_quoted():
    source = inspect.getsource(Database.report_node_status)
    assert "ss_node_info (node_id, uptime, `load`, log_time)" in source
    assert "ss_node_info (node_id, uptime, load, log_time)" not in source
