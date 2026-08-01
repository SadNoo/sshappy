package panel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

var processStartedAt = time.Now()

const (
	trafficSQLBatchSize = 50
	aliveIPSQLBatchSize = 500
)

type Database struct {
	db *sql.DB
	// lockDB keeps advisory-lock sessions separate from cancellable traffic
	// transactions. The MySQL driver cancels an in-flight query by closing its
	// connection, which may otherwise delay RELEASE_LOCK behind that query.
	lockDB *sql.DB
	config Config
}

// ErrNodeNotAuthorized marks node state that is authoritative and must not be
// treated like a temporary database failure. Keeping the previous node active
// after this error would bypass a panel-side revoke or bandwidth limit.
var ErrNodeNotAuthorized = errors.New("node is not authorized to serve traffic")

func OpenDatabase(config Config) (*Database, error) {
	return OpenDatabaseContext(context.Background(), config)
}

func OpenDatabaseContext(ctx context.Context, config Config) (*Database, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tlsMode, err := mysqlTLSMode(config)
	if err != nil {
		return nil, err
	}
	driverConfig := mysqlDriverConfig(config, tlsMode)
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(3 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := validateDatabaseSchemaContext(ctx, db, config.MySQLDB); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = db.Close()
		return nil, err
	}
	lockDB, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	lockDB.SetMaxOpenConns(4)
	lockDB.SetMaxIdleConns(1)
	lockDB.SetConnMaxLifetime(3 * time.Minute)
	return &Database{db: db, lockDB: lockDB, config: config}, nil
}

func mysqlDriverConfig(config Config, tlsMode string) *mysql.Config {
	driverConfig := mysql.NewConfig()
	driverConfig.User = config.MySQLUser
	driverConfig.Passwd = config.MySQLPassword
	driverConfig.Net = "tcp"
	driverConfig.Addr = net.JoinHostPort(config.MySQLHost, strconv.Itoa(config.MySQLPort))
	driverConfig.DBName = config.MySQLDB
	driverConfig.Params = map[string]string{"charset": "utf8mb4"}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.Local
	driverConfig.TLSConfig = tlsMode
	driverConfig.Timeout = time.Duration(config.MySQLConnectTimeoutSeconds) * time.Second
	driverConfig.ReadTimeout = time.Duration(config.MySQLIOTimeoutSeconds) * time.Second
	driverConfig.WriteTimeout = time.Duration(config.MySQLIOTimeoutSeconds) * time.Second
	return driverConfig
}

const (
	mysqlSchemaVersion       = 1
	mysqlSchemaMigrationName = "0001_traffic_batch"
	mysqlMigrationPath       = "migrations/mysql/0001_traffic_batch.sql"
)

// ErrDatabaseMigrationRequired marks a missing or incompatible database
// schema. OpenDatabase only validates the schema; migrations must be applied
// separately with an account that is allowed to execute DDL.
var ErrDatabaseMigrationRequired = errors.New("database schema migration required")

type mysqlColumnMetadata struct {
	dataType   string
	columnType string
	nullable   string
	charset    string
	collation  string
}

type mysqlIndexColumnMetadata struct {
	columnName string
	nonUnique  bool
	sequence   int
	prefix     sql.NullInt64
	indexType  string
}

type mysqlTableMetadata struct {
	engine  string
	columns map[string]mysqlColumnMetadata
	indexes map[string][]mysqlIndexColumnMetadata
}

func validateDatabaseSchemaContext(ctx context.Context, db *sql.DB, schema string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	migrationTable, found, err := inspectMySQLTableContext(ctx, db, schema, "sshappy_schema_migrations")
	if err != nil {
		return fmt.Errorf("failed to inspect database migration table: %w", err)
	}
	if !found {
		return databaseMigrationRequired("migration table is missing")
	}
	if err := validateMigrationTableMetadata(migrationTable); err != nil {
		return err
	}

	var migrationCount, currentVersion int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(version), 0)
		FROM sshappy_schema_migrations
	`).Scan(&migrationCount, &currentVersion); err != nil {
		return fmt.Errorf("failed to read database schema version: %w", err)
	}
	if migrationCount != mysqlSchemaVersion || currentVersion != mysqlSchemaVersion {
		return databaseMigrationRequired(fmt.Sprintf(
			"schema version is incompatible (expected %d applied migration, found %d, latest version %d)",
			mysqlSchemaVersion,
			migrationCount,
			currentVersion,
		))
	}

	var migrationName string
	if err := db.QueryRowContext(ctx, `
		SELECT name
		FROM sshappy_schema_migrations
		WHERE version = ?
	`, mysqlSchemaVersion).Scan(&migrationName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return databaseMigrationRequired(fmt.Sprintf("schema migration version %d is missing", mysqlSchemaVersion))
		}
		return fmt.Errorf("failed to read database schema migration record: %w", err)
	}
	if migrationName != mysqlSchemaMigrationName {
		return databaseMigrationRequired(fmt.Sprintf("schema migration version %d has an unexpected name", mysqlSchemaVersion))
	}

	trafficBatchTable, found, err := inspectMySQLTableContext(ctx, db, schema, "sshappy_traffic_batch")
	if err != nil {
		return fmt.Errorf("failed to inspect traffic batch table: %w", err)
	}
	if !found {
		return databaseMigrationRequired("traffic batch table is missing")
	}
	return validateTrafficBatchTableMetadata(trafficBatchTable)
}

func inspectMySQLTableContext(ctx context.Context, db *sql.DB, schema, table string) (mysqlTableMetadata, bool, error) {
	metadata := mysqlTableMetadata{
		columns: make(map[string]mysqlColumnMetadata),
		indexes: make(map[string][]mysqlIndexColumnMetadata),
	}
	if err := db.QueryRowContext(ctx, `
		SELECT engine
		FROM information_schema.tables
		WHERE table_schema = ? AND table_name = ? AND table_type = 'BASE TABLE'
	`, schema, table).Scan(&metadata.engine); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return metadata, false, nil
		}
		return metadata, false, err
	}

	columnRows, err := db.QueryContext(ctx, `
		SELECT column_name, data_type, column_type, is_nullable,
		       COALESCE(character_set_name, ''), COALESCE(collation_name, '')
		FROM information_schema.columns
		WHERE table_schema = ? AND table_name = ?
	`, schema, table)
	if err != nil {
		return metadata, false, err
	}
	for columnRows.Next() {
		var name string
		var column mysqlColumnMetadata
		if err := columnRows.Scan(
			&name,
			&column.dataType,
			&column.columnType,
			&column.nullable,
			&column.charset,
			&column.collation,
		); err != nil {
			_ = columnRows.Close()
			return metadata, false, err
		}
		metadata.columns[name] = column
	}
	if err := columnRows.Close(); err != nil {
		return metadata, false, err
	}
	if err := columnRows.Err(); err != nil {
		return metadata, false, err
	}

	indexRows, err := db.QueryContext(ctx, `
		SELECT index_name, non_unique, seq_in_index, column_name, sub_part, index_type
		FROM information_schema.statistics
		WHERE table_schema = ? AND table_name = ?
		ORDER BY index_name, seq_in_index
	`, schema, table)
	if err != nil {
		return metadata, false, err
	}
	for indexRows.Next() {
		var name string
		var nonUnique int
		var columnName sql.NullString
		var column mysqlIndexColumnMetadata
		if err := indexRows.Scan(
			&name,
			&nonUnique,
			&column.sequence,
			&columnName,
			&column.prefix,
			&column.indexType,
		); err != nil {
			_ = indexRows.Close()
			return metadata, false, err
		}
		column.columnName = columnName.String
		column.nonUnique = nonUnique != 0
		metadata.indexes[name] = append(metadata.indexes[name], column)
	}
	if err := indexRows.Close(); err != nil {
		return metadata, false, err
	}
	if err := indexRows.Err(); err != nil {
		return metadata, false, err
	}
	return metadata, true, nil
}

func validateMigrationTableMetadata(table mysqlTableMetadata) error {
	if !strings.EqualFold(table.engine, "InnoDB") {
		return databaseMigrationRequired("migration table must use InnoDB")
	}
	expectedColumns := map[string]mysqlColumnMetadata{
		"version": {
			dataType:   "bigint",
			columnType: "bigint unsigned",
			nullable:   "NO",
		},
		"name": {
			dataType:   "varchar",
			columnType: "varchar(128)",
			nullable:   "NO",
			charset:    "ascii",
			collation:  "ascii_bin",
		},
		"applied_at": {
			dataType:   "timestamp",
			columnType: "timestamp(6)",
			nullable:   "NO",
		},
	}
	if err := validateRequiredColumns(table.columns, expectedColumns); err != nil {
		return databaseMigrationRequired("migration table " + err.Error())
	}
	if !mysqlIndexMatches(table.indexes["PRIMARY"], false, "version") {
		return databaseMigrationRequired("migration table primary key is incompatible")
	}
	return nil
}

func validateTrafficBatchTableMetadata(table mysqlTableMetadata) error {
	if !strings.EqualFold(table.engine, "InnoDB") {
		return databaseMigrationRequired("traffic batch table must use InnoDB")
	}
	expectedColumns := map[string]mysqlColumnMetadata{
		"batch_id": {
			dataType:   "char",
			columnType: "char(32)",
			nullable:   "NO",
			charset:    "ascii",
			collation:  "ascii_bin",
		},
		"node_id": {
			dataType:   "int",
			columnType: "int",
			nullable:   "NO",
		},
		"created_at": {
			dataType:   "bigint",
			columnType: "bigint",
			nullable:   "NO",
		},
	}
	if err := validateRequiredColumns(table.columns, expectedColumns); err != nil {
		return databaseMigrationRequired("traffic batch table " + err.Error())
	}
	if !mysqlIndexMatches(table.indexes["PRIMARY"], false, "batch_id") {
		return databaseMigrationRequired("traffic batch table primary key is incompatible")
	}
	if !mysqlIndexMatches(table.indexes["node_created_at"], true, "node_id", "created_at") {
		return databaseMigrationRequired("traffic batch table node_created_at index is incompatible")
	}
	return nil
}

func validateRequiredColumns(actual, expected map[string]mysqlColumnMetadata) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("has %d columns, want exactly %d", len(actual), len(expected))
	}
	for name, expectedColumn := range expected {
		actualColumn, found := actual[name]
		if !found {
			return fmt.Errorf("is missing column %s", name)
		}
		if !strings.EqualFold(actualColumn.dataType, expectedColumn.dataType) ||
			!strings.EqualFold(actualColumn.columnType, expectedColumn.columnType) ||
			!strings.EqualFold(actualColumn.nullable, expectedColumn.nullable) ||
			!strings.EqualFold(actualColumn.charset, expectedColumn.charset) ||
			!strings.EqualFold(actualColumn.collation, expectedColumn.collation) {
			return fmt.Errorf("has incompatible column %s", name)
		}
	}
	return nil
}

func mysqlIndexMatches(actual []mysqlIndexColumnMetadata, nonUnique bool, columns ...string) bool {
	if len(actual) != len(columns) {
		return false
	}
	for index, column := range actual {
		if column.nonUnique != nonUnique ||
			column.sequence != index+1 ||
			column.columnName != columns[index] ||
			column.prefix.Valid ||
			!strings.EqualFold(column.indexType, "BTREE") {
			return false
		}
	}
	return true
}

func databaseMigrationRequired(reason string) error {
	return fmt.Errorf(
		"%w: %s; apply %s with a database migration account before starting sshappy",
		ErrDatabaseMigrationRequired,
		reason,
		mysqlMigrationPath,
	)
}

const mysqlTLSConfigName = "sshappy-panel-mysql"

func mysqlTLSMode(config Config) (string, error) {
	mode := strings.ToLower(config.MySQLTLSMode)
	if mode == "" || mode == "auto" {
		if strings.EqualFold(config.MySQLHost, "localhost") {
			return "false", nil
		}
		if ip := net.ParseIP(config.MySQLHost); ip != nil && ip.IsLoopback() {
			return "false", nil
		}
		mode = "required"
	}

	switch mode {
	case "disabled":
		return "false", nil
	case "preferred":
		return mode, nil
	case "required":
		return "true", nil
	case "verify":
		data, err := os.ReadFile(config.MySQLTLSCA)
		if err != nil {
			return "", fmt.Errorf("failed to read MYSQL_TLS_CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return "", fmt.Errorf("MYSQL_TLS_CA does not contain a valid certificate")
		}
		if err := mysql.RegisterTLSConfig(mysqlTLSConfigName, &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: config.MySQLHost,
		}); err != nil {
			return "", fmt.Errorf("failed to register MySQL TLS config: %w", err)
		}
		return mysqlTLSConfigName, nil
	default:
		return "", fmt.Errorf("unsupported MySQL TLS mode %q", config.MySQLTLSMode)
	}
}

func (d *Database) Close() error {
	var lockErr error
	if d.lockDB != nil && d.lockDB != d.db {
		lockErr = d.lockDB.Close()
	}
	return errors.Join(lockErr, d.db.Close())
}

func (d *Database) Stats() sql.DBStats {
	return d.db.Stats()
}

func (d *Database) LoadNode() (Node, error) {
	return d.LoadNodeContext(context.Background())
}

func (d *Database) LoadNodeContext(ctx context.Context) (Node, error) {
	var node Node
	if err := ctx.Err(); err != nil {
		return node, err
	}
	var bandwidth, bandwidthLimit int64
	err := d.db.QueryRowContext(ctx, `
		SELECT id, node_group, node_class, node_speedlimit, traffic_rate, sort, server,
		       node_bandwidth, node_bandwidth_limit
		FROM ss_node
		WHERE id = ?
	`, d.config.NodeID).Scan(
		&node.ID,
		&node.Group,
		&node.Class,
		&node.SpeedLimit,
		&node.TrafficRate,
		&node.Sort,
		&node.Server,
		&bandwidth,
		&bandwidthLimit,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return node, fmt.Errorf("%w: node %d does not exist", ErrNodeNotAuthorized, d.config.NodeID)
		}
		return node, err
	}
	return validateLoadedNode(node, bandwidth, bandwidthLimit)
}

func validateLoadedNode(node Node, bandwidth, bandwidthLimit int64) (Node, error) {
	if bandwidthLimit != 0 && bandwidth >= bandwidthLimit {
		return node, fmt.Errorf("%w: node %d exceeded its bandwidth limit", ErrNodeNotAuthorized, node.ID)
	}
	if node.Sort != 14 {
		return node, fmt.Errorf("%w: node %d must be sort=14", ErrNodeNotAuthorized, node.ID)
	}
	_, port, serverKeyB64, err := parseSSSinglePort(node.Server)
	if err != nil {
		return node, fmt.Errorf("%w: %v", ErrNodeNotAuthorized, err)
	}
	serverKey, err := decodePSK(serverKeyB64)
	if err != nil {
		return node, fmt.Errorf("%w: node %d has an invalid server key", ErrNodeNotAuthorized, node.ID)
	}
	node.ListenPort = port
	node.ServerKeyB64 = serverKeyB64
	node.ServerKey = serverKey
	if node.TrafficRate == 0 {
		node.TrafficRate = 1
	}
	if node.TrafficRate < 0 || math.IsNaN(node.TrafficRate) || math.IsInf(node.TrafficRate, 0) {
		return node, fmt.Errorf("%w: node %d has invalid traffic rate", ErrNodeNotAuthorized, node.ID)
	}
	return node, nil
}

func (d *Database) LoadUsers(node Node) ([]User, error) {
	return d.LoadUsersContext(context.Background(), node)
}

func (d *Database) LoadUsersContext(ctx context.Context, node Node) ([]User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conditions := []string{"enable = 1", "expire_in > NOW()", "transfer_enable > u + d"}
	var args []any
	if node.Group == 0 {
		conditions = append(conditions, "(class >= ? OR is_admin = 1)")
		args = append(args, node.Class)
	} else {
		conditions = append(conditions, "((class >= ? AND node_group = ?) OR is_admin = 1)")
		args = append(args, node.Class, node.Group)
	}
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, email, passwd, forbidden_ip, forbidden_port, disconnect_ip, node_speedlimit
		FROM user
		WHERE `+strings.Join(conditions, " AND "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0, 1024)
	for rows.Next() {
		var user User
		var forbiddenIP, forbiddenPort, disconnectIP sql.NullString
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Passwd,
			&forbiddenIP,
			&forbiddenPort,
			&disconnectIP,
			&user.NodeSpeedLimit,
		); err != nil {
			return nil, err
		}
		user.ForbiddenIP = forbiddenIP.String
		user.ForbiddenPort = forbiddenPort.String
		user.DisconnectIP = disconnectIP.String
		user.UserKey, user.UserKeyB64 = deriveUserKey(user.ID, user.Passwd, node.ID, node.ServerKeyB64)
		users = append(users, user)
	}
	return users, rows.Err()
}

func (d *Database) ReportTraffic(node Node, batchID string, traffic []TrafficDelta) error {
	return d.ReportTrafficContext(context.Background(), node, batchID, traffic)
}

func (d *Database) ReportTrafficContext(ctx context.Context, node Node, batchID string, traffic []TrafficDelta) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(traffic) == 0 {
		return nil
	}
	release, err := d.acquireTrafficBatchLockContext(ctx, node.ID, batchID)
	if err != nil {
		return err
	}
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return errors.Join(
			fmt.Errorf("failed to reserve traffic reporting connection: %w", err),
			release(),
		)
	}
	defer conn.Close()
	defer func() {
		err = errors.Join(err, release())
	}()

	committed, err := d.trafficBatchCommittedContext(ctx, conn, node.ID, batchID)
	if err != nil {
		return err
	}
	if committed {
		return nil
	}

	billed, err := prepareBilledTraffic(node.TrafficRate, traffic)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	chunkIDs := make([]string, 0, (len(billed)+trafficSQLBatchSize-1)/trafficSQLBatchSize)
	for start := 0; start < len(billed); start += trafficSQLBatchSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+trafficSQLBatchSize, len(billed))
		chunkID := trafficChunkID(batchID, node.ID, len(chunkIDs))
		chunkIDs = append(chunkIDs, chunkID)
		if err := d.reportTrafficChunkContext(ctx, conn, node, chunkID, billed[start:end], now); err != nil {
			return fmt.Errorf("traffic chunk %d/%d failed: %w", len(chunkIDs), (len(billed)+trafficSQLBatchSize-1)/trafficSQLBatchSize, err)
		}
	}
	return d.finalizeTrafficBatchContext(ctx, conn, node.ID, batchID, chunkIDs, now)
}

func (d *Database) acquireTrafficBatchLockContext(ctx context.Context, nodeID int, batchID string) (func() error, error) {
	timeoutSeconds := d.config.MySQLIOTimeoutSeconds
	if timeoutSeconds < 1 {
		timeoutSeconds = 30
	}
	lockCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds+1)*time.Second)
	defer cancel()
	lockDB := d.lockDB
	if lockDB == nil {
		lockDB = d.db
	}
	conn, err := lockDB.Conn(lockCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve traffic lock connection: %w", err)
	}
	lockName := trafficBatchLockName(nodeID, batchID)
	var acquired sql.NullInt64
	if err := conn.QueryRowContext(lockCtx, "SELECT GET_LOCK(?, ?)", lockName, timeoutSeconds).Scan(&acquired); err != nil {
		// The server may have granted the lock before the response was lost.
		// Discard the physical connection instead of returning it to the pool.
		discardSQLConn(conn)
		return nil, fmt.Errorf("failed to acquire traffic batch lock: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		_ = conn.Close()
		return nil, fmt.Errorf("timed out acquiring traffic batch lock")
	}
	release := func() error {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		var released sql.NullInt64
		releaseErr := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", lockName).Scan(&released)
		if releaseErr != nil || !released.Valid || released.Int64 != 1 {
			// A sql.Conn.Close returns the underlying connection to the pool. Mark it
			// bad instead so an ambiguously held advisory lock cannot leak into the
			// pool after a failed RELEASE_LOCK.
			discardSQLConn(conn)
			if releaseErr != nil {
				return fmt.Errorf("failed to release traffic batch lock: %w", releaseErr)
			}
			return errors.New("traffic batch lock was not owned at release")
		}
		return conn.Close()
	}
	return release, nil
}

func discardSQLConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

func trafficBatchLockName(nodeID int, batchID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", nodeID, batchID)))
	return "sshappy:traffic:" + hex.EncodeToString(sum[:16])
}

func (d *Database) trafficBatchCommittedContext(ctx context.Context, conn *sql.Conn, nodeID int, batchID string) (bool, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx,
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		batchID,
		nodeID,
		time.Now().Unix(),
	)
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if err := ctx.Err(); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	if err := tx.Rollback(); err != nil {
		return false, err
	}
	return inserted == 0, nil
}

func (d *Database) reportTrafficChunkContext(ctx context.Context, conn *sql.Conn, node Node, chunkID string, batch []billedTrafficDelta, now int64) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		chunkID,
		node.ID,
		now,
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		return nil
	}
	query, args := userTrafficUpdateStatement(batch, now)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	query, args = trafficLogInsertStatement(batch, node, now)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	total, err := checkedRawTrafficTotal(batch)
	if err != nil {
		return fmt.Errorf("invalid traffic chunk total: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE ss_node
		SET node_heartbeat = ?, node_bandwidth = node_bandwidth + ?
		WHERE id = ?
	`, now, total, node.ID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *Database) finalizeTrafficBatchContext(ctx context.Context, conn *sql.Conn, nodeID int, batchID string, chunkIDs []string, now int64) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"INSERT IGNORE INTO sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, ?, ?)",
		batchID,
		nodeID,
		now,
	); err != nil {
		return err
	}
	if len(chunkIDs) > 0 {
		var query strings.Builder
		query.WriteString("DELETE FROM sshappy_traffic_batch WHERE node_id = ? AND batch_id IN (")
		appendSQLPlaceholders(&query, len(chunkIDs), 1)
		query.WriteByte(')')
		args := make([]any, 0, len(chunkIDs)+1)
		args = append(args, nodeID)
		for _, chunkID := range chunkIDs {
			args = append(args, chunkID)
		}
		if _, err := tx.ExecContext(ctx, query.String(), args...); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func trafficChunkID(batchID string, nodeID, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", batchID, nodeID, index)))
	return hex.EncodeToString(sum[:16])
}

type billedTrafficDelta struct {
	TrafficDelta
	BilledUpload   int64
	BilledDownload int64
	TrafficText    string
}

func prepareBilledTraffic(rate float64, traffic []TrafficDelta) ([]billedTrafficDelta, error) {
	if rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return nil, errors.New("traffic rate must be a finite non-negative number")
	}
	canonical, err := canonicalTrafficDeltas(traffic)
	if err != nil {
		return nil, err
	}
	billed := make([]billedTrafficDelta, 0, len(canonical))
	for _, delta := range canonical {
		rawTotal, err := checkedNonnegativeTrafficAdd(delta.Upload, delta.Download)
		if err != nil {
			return nil, fmt.Errorf("traffic total overflow for user %d", delta.UserID)
		}
		billedUpload, err := checkedScaleTraffic(delta.Upload, rate)
		if err != nil {
			return nil, fmt.Errorf("billed upload overflow for user %d: %w", delta.UserID, err)
		}
		billedDownload, err := checkedScaleTraffic(delta.Download, rate)
		if err != nil {
			return nil, fmt.Errorf("billed download overflow for user %d: %w", delta.UserID, err)
		}
		billedTotal, err := checkedScaleTraffic(rawTotal, rate)
		if err != nil {
			return nil, fmt.Errorf("billed traffic total overflow for user %d: %w", delta.UserID, err)
		}
		billed = append(billed, billedTrafficDelta{
			TrafficDelta:   delta,
			BilledUpload:   billedUpload,
			BilledDownload: billedDownload,
			TrafficText:    flowAutoShow(billedTotal),
		})
	}
	for start := 0; start < len(billed); start += trafficSQLBatchSize {
		end := min(start+trafficSQLBatchSize, len(billed))
		if _, err := checkedRawTrafficTotal(billed[start:end]); err != nil {
			return nil, fmt.Errorf("traffic chunk %d raw byte total overflow: %w", start/trafficSQLBatchSize+1, err)
		}
	}
	return billed, nil
}

func checkedScaleTraffic(value int64, rate float64) (int64, error) {
	if value < 0 || rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return 0, errors.New("traffic value and rate must be finite and non-negative")
	}
	if value == 0 || rate == 0 {
		return 0, nil
	}
	if rate == 1 {
		return value, nil
	}
	product := float64(value) * rate
	// float64(math.MaxInt64) rounds to 2^63, which is already outside the
	// int64 range. Reject the boundary rather than relying on implementation-
	// specific out-of-range float-to-integer conversion.
	if math.IsInf(product, 0) || math.IsNaN(product) || product >= float64(math.MaxInt64) {
		return 0, errors.New("scaled traffic exceeds int64")
	}
	return int64(product), nil
}

func checkedNonnegativeTrafficAdd(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, errors.New("traffic byte total exceeds int64")
	}
	return left + right, nil
}

func checkedRawTrafficTotal(batch []billedTrafficDelta) (int64, error) {
	var total int64
	for _, delta := range batch {
		userTotal, err := checkedNonnegativeTrafficAdd(delta.Upload, delta.Download)
		if err != nil {
			return 0, err
		}
		total, err = checkedNonnegativeTrafficAdd(total, userTotal)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func userTrafficUpdateStatement(batch []billedTrafficDelta, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(batch)*5+1)
	query.WriteString("UPDATE user SET u = u + CASE id")
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.UserID, delta.BilledUpload)
	}
	query.WriteString(" ELSE 0 END, d = d + CASE id")
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.UserID, delta.BilledDownload)
	}
	query.WriteString(" ELSE 0 END, t = ? WHERE id IN (")
	args = append(args, now)
	appendSQLPlaceholders(&query, len(batch), 1)
	query.WriteByte(')')
	for _, delta := range batch {
		args = append(args, delta.UserID)
	}
	return query.String(), args
}

func trafficLogInsertStatement(batch []billedTrafficDelta, node Node, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(batch)*7)
	query.WriteString("INSERT INTO user_traffic_log (user_id, u, d, node_id, rate, traffic, log_time) VALUES ")
	appendSQLPlaceholders(&query, len(batch), 7)
	for _, delta := range batch {
		args = append(args, delta.UserID, delta.Upload, delta.Download, node.ID, node.TrafficRate, delta.TrafficText, now)
	}
	return query.String(), args
}

func appendSQLPlaceholders(builder *strings.Builder, rows, columns int) {
	for row := 0; row < rows; row++ {
		if row > 0 {
			builder.WriteByte(',')
		}
		if columns > 1 {
			builder.WriteByte('(')
		}
		for column := 0; column < columns; column++ {
			if column > 0 {
				builder.WriteByte(',')
			}
			builder.WriteByte('?')
		}
		if columns > 1 {
			builder.WriteByte(')')
		}
	}
}

func (d *Database) CleanupTrafficBatches(nodeID, retentionDays int) (int64, error) {
	return d.CleanupTrafficBatchesContext(context.Background(), nodeID, retentionDays)
}

func (d *Database) CleanupTrafficBatchesContext(ctx context.Context, nodeID, retentionDays int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if retentionDays == 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	const deleteBatchSize = 5000
	var deletedTotal int64
	for {
		result, err := d.db.ExecContext(ctx, `
			DELETE FROM sshappy_traffic_batch
			WHERE node_id = ? AND created_at < ?
			LIMIT ?
		`, nodeID, cutoff, deleteBatchSize)
		if err != nil {
			return deletedTotal, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return deletedTotal, err
		}
		deletedTotal += deleted
		if deleted < deleteBatchSize {
			return deletedTotal, nil
		}
	}
}

func (d *Database) ReportAliveIPs(node Node, alive map[int]map[string]struct{}) error {
	return d.ReportAliveIPsContext(context.Background(), node, alive)
}

func (d *Database) ReportAliveIPsContext(ctx context.Context, node Node, alive map[int]map[string]struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(alive) == 0 {
		return nil
	}
	now := time.Now().Unix()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	records := make([]aliveIPRecord, 0)
	for userID, ips := range alive {
		for ip := range ips {
			records = append(records, aliveIPRecord{UserID: userID, IP: ip})
		}
	}
	for start := 0; start < len(records); start += aliveIPSQLBatchSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+aliveIPSQLBatchSize, len(records))
		query, args := aliveIPInsertStatement(records[start:end], node.ID, now)
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

type aliveIPRecord struct {
	UserID int
	IP     string
}

func aliveIPInsertStatement(records []aliveIPRecord, nodeID int, now int64) (string, []any) {
	var query strings.Builder
	args := make([]any, 0, len(records)*4)
	query.WriteString("INSERT INTO alive_ip (nodeid, userid, ip, datetime) VALUES ")
	appendSQLPlaceholders(&query, len(records), 4)
	for _, record := range records {
		args = append(args, nodeID, record.UserID, record.IP, now)
	}
	return query.String(), args
}

func (d *Database) ReportNodeStatus(node Node, online int) error {
	return d.ReportNodeStatusContext(context.Background(), node, online)
}

func (d *Database) ReportNodeStatusContext(ctx context.Context, node Node, online int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().Unix()
	uptime := int64(time.Since(processStartedAt).Seconds())
	load := "0.00"
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			load = fields[0]
		}
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO ss_node_online_log (node_id, online_user, log_time) VALUES (?, ?, ?)",
		node.ID,
		online,
		now,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO ss_node_info (node_id, uptime, `load`, log_time) VALUES (?, ?, ?, ?)",
		node.ID,
		uptime,
		load,
		now,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE ss_node SET node_heartbeat = ? WHERE id = ?", now, node.ID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func parseSSSinglePort(value string) (host string, port int, key string, err error) {
	parts := strings.Split(value, ";")
	if len(parts) > 0 {
		host = parts[0]
	}
	port = 443
	if len(parts) >= 2 && parts[1] != "" && parts[1] != "0" {
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return
		}
	}
	if len(parts) >= 3 {
		key = parts[2]
	}
	switch {
	case host == "":
		err = fmt.Errorf("ss_node.server host is empty")
	case port < 1 || port > 65535:
		err = fmt.Errorf("ss_node.server port must be between 1 and 65535")
	case key == "":
		err = fmt.Errorf("ss_node.server server_key is empty")
	}
	return
}

func flowAutoShow(value int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	amount := float64(value)
	for i, unit := range units {
		if amount < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.2f%s", math.Round(amount*100)/100, unit)
		}
		amount /= 1024
	}
	return fmt.Sprintf("%.2fPB", amount)
}
