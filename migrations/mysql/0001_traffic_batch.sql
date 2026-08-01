-- Apply this migration with a dedicated migration account before starting 4.4.
-- It is safe for a fresh database and for a 4.3 database that already has the
-- current sshappy_traffic_batch table. 4.4 validates the existing table's
-- engine, required columns, primary key, and node_created_at index at startup.

CREATE TABLE IF NOT EXISTS sshappy_schema_migrations (
    version BIGINT UNSIGNED NOT NULL,
    name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    applied_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (version)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sshappy_traffic_batch (
    batch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    node_id INT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (batch_id),
    KEY node_created_at (node_id, created_at)
) ENGINE=InnoDB;

INSERT IGNORE INTO sshappy_schema_migrations (version, name)
VALUES (1, '0001_traffic_batch');
