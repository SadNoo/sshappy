# MySQL schema initialization for 4.4.1

Version 4.4.1 fixes the 4.4.0 requirement that every deployment manually create a migration-record table before the image could start. The default `MYSQL_SCHEMA_MODE=auto` behaves as follows:

- a compatible 4.3.1 `sshappy_traffic_batch` table with no migration table is accepted as implicit schema version 1 with no DDL;
- if both sshappy-owned auxiliary tables are absent, the runtime initializes them from the exact embedded release migration under a schema-specific MySQL advisory lock;
- an interrupted initialization with an exact, empty migration table can be completed safely; and
- any existing incompatible table, wrong migration record, unknown version or declared-but-missing table is rejected without `DROP`, `ALTER` or overwrite.

Set `MYSQL_SCHEMA_MODE=strict` to retain the 4.4.0 policy: runtime DDL is disabled and the complete migration must be applied before startup.

Migration `migrations/mysql/0001_traffic_batch.sql` creates:

- `sshappy_schema_migrations`, which records schema version 1; and
- `sshappy_traffic_batch`, the idempotency marker table already used by 4.3.1.

The migration is safe when the 4.3.1 marker table already has the compatible definition: `CREATE TABLE IF NOT EXISTS` preserves its rows, and the migration record is then added. It does not repair a table whose engine, columns, collation, primary key or index differs from the required shape; 4.4.1 detects and rejects such a schema.

## Locate and verify the SQL

The same SQL file is shipped in three places:

- repository: `migrations/mysql/0001_traffic_batch.sql`;
- every 4.4 release archive: `migrations/mysql/0001_traffic_batch.sql` inside the archive; and
- Docker image: `/usr/share/doc/sshappy/migrations/mysql/0001_traffic_batch.sql`, mode `0444`.

Use the file from the same Git tag, release archive or image digest as the binary being deployed. Review it before execution. It contains schema only and must never be edited to embed a password or deployment secret.

## Optional strict-mode plaintext procedure

The target database cannot use TLS. Perform this only across a trusted private network protected from public access. Manual migration is optional in default auto mode, but recommended when the long-running account must never hold DDL privileges. Stop 4.3.1 and back up the schema before migration. Use a dedicated account with the DDL privileges required for these two tables; `--password` prompts interactively so the secret does not appear in shell history or the process arguments.

```sh
mysql \
  --protocol=TCP \
  --host=127.0.0.1 \
  --port=3306 \
  --user=sshappy_migrator \
  --password \
  --ssl-mode=DISABLED \
  sspanel < migrations/mysql/0001_traffic_batch.sql
```

Use the actual private database host and schema name in place of the examples. Do not use the migration account as the long-running service account.

Verify the applied version with the same prompted connection:

```sh
mysql \
  --protocol=TCP \
  --host=127.0.0.1 \
  --port=3306 \
  --user=sshappy_migrator \
  --password \
  --ssl-mode=DISABLED \
  --database=sspanel \
  --execute='SELECT version, name FROM sshappy_schema_migrations ORDER BY version; SHOW CREATE TABLE sshappy_traffic_batch;'
```

The migration query must return version `1` with name `0001_traffic_batch`. The 4.4.1 runtime then independently verifies both table definitions.

## Runtime configuration

For a pre-migrated or compatible 4.3.1 schema, grant the runtime account only the existing SSPanel data permissions and the required read/write access to `sshappy_traffic_batch`; it needs metadata visibility but no DDL privileges. For a genuinely fresh sshappy-owned schema in auto mode, grant `CREATE` and `INSERT` for the first startup, verify version 1, then revoke unnecessary DDL privileges. Configure the plaintext connection explicitly:

```sh
MYSQL_TLS_MODE=disabled
MYSQL_SCHEMA_MODE=auto
```

The 4.4.1 Docker image defaults to `disabled` for this plaintext-only deployment. Source-built binaries retain the `auto` fallback; TLS-capable installations can select `auto`, `required` or `verify`. Keep credentials in a secret manager or protected environment file, never in the migration SQL, image, source tree or command line.

## Compatibility and rollback

Leave both migration tables in place when rolling back to 4.3.1. The added migration table is ignored by 4.3.1, and its compatible traffic marker table remains required for idempotent traffic reporting. Dropping either table during rollback can break accounting recovery.

Database compatibility does not make the local outbox formats compatible. Drain the 4.4.1 SQLite outbox completely before starting 4.3.1, restore the legacy JSON path, and never run both versions against one state directory. See [operations and rollback](operations.md).
