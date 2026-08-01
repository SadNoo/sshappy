# MySQL migration for 4.4

Version 4.4 separates schema ownership from runtime operation. `sstest` validates the schema at startup but never creates or alters tables. Apply every repository migration in numeric order before starting the new binary or image.

Migration `migrations/mysql/0001_traffic_batch.sql` creates:

- `sshappy_schema_migrations`, which records schema version 1; and
- `sshappy_traffic_batch`, the idempotency marker table already used by 4.3.1.

The migration is safe when the 4.3.1 marker table already has the compatible definition: `CREATE TABLE IF NOT EXISTS` preserves its rows, and the migration record is then added. It does not repair a table whose engine, columns, collation, primary key or index differs from the required shape; 4.4 detects and rejects such a schema.

## Locate and verify the SQL

The same SQL file is shipped in three places:

- repository: `migrations/mysql/0001_traffic_batch.sql`;
- every 4.4 release archive: `migrations/mysql/0001_traffic_batch.sql` inside the archive; and
- Docker image: `/usr/share/doc/sshappy/migrations/mysql/0001_traffic_batch.sql`, mode `0444`.

Use the file from the same Git tag, release archive or image digest as the binary being deployed. Review it before execution. It contains schema only and must never be edited to embed a password or deployment secret.

## Plaintext-only database procedure

The target database cannot use TLS. Perform this only across a trusted private network protected from public access. Stop 4.3.1 and back up the schema before migration. Use a dedicated account with the DDL privileges required for these two tables; `--password` prompts interactively so the secret does not appear in shell history or the process arguments.

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

The migration query must return version `1` with name `0001_traffic_batch`. The 4.4 runtime then independently verifies both table definitions.

## Runtime configuration

Grant the runtime account only the existing SSPanel data permissions and the required read/write access to `sshappy_traffic_batch`; it needs read access to `sshappy_schema_migrations` and `information_schema` metadata but no DDL privileges. Configure the plaintext connection explicitly:

```sh
MYSQL_TLS_MODE=disabled
```

The application default `auto` requires TLS for a non-loopback host, so omitting this variable can correctly make a remote plaintext deployment fail startup. Keep credentials in a secret manager or protected environment file, never in the migration SQL, image, source tree or command line.

## Compatibility and rollback

Leave both migration tables in place when rolling back to 4.3.1. The added migration table is ignored by 4.3.1, and its compatible traffic marker table remains required for idempotent traffic reporting. Dropping either table during rollback can break accounting recovery.

Database compatibility does not make the local outbox formats compatible. Drain the 4.4 SQLite outbox completely before starting 4.3.1, restore the legacy JSON path, and never run both versions against one state directory. See [operations and rollback](operations.md).
