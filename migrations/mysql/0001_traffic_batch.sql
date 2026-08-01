-- 4.4.1 embeds this exact migration for automatic first-start initialization.
-- Operators may instead apply it with a dedicated migration account and set
-- MYSQL_SCHEMA_MODE=strict. It is safe for a fresh sshappy-owned schema and for
-- a 4.3 database that already has the current sshappy_traffic_batch table.

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
