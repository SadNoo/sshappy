package panel

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLSchemaAutoInitializationAndLegacyCompatibility(t *testing.T) {
	dsn := os.Getenv("SSHAPPY_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("SSHAPPY_TEST_MYSQL_DSN is not set")
	}
	driverConfig, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminDB, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()

	const (
		schema          = "sshappy_auto_bootstrap_test"
		runtimeUser     = "sshappy_auto_validator"
		runtimePassword = "auto-validator-test-password"
	)
	if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + schema + "`"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE `" + schema + "`"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + schema + "`"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	}()

	config := mysqlIntegrationConfig(t, driverConfig, schema, driverConfig.User, driverConfig.Passwd, "auto")
	database, err := OpenDatabaseContext(t.Context(), config)
	if err != nil {
		t.Fatalf("automatic initialization on a fresh sshappy schema: %v", err)
	}
	if database.schemaState != databaseSchemaInitialized {
		t.Fatalf("schema state = %d, want initialized", database.schemaState)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var migrations int
	if err := adminDB.QueryRow("SELECT COUNT(*) FROM `" + schema + "`.sshappy_schema_migrations WHERE version = 1 AND name = '0001_traffic_batch'").Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 1 {
		t.Fatalf("migration records = %d, want 1", migrations)
	}
	const markerID = "0123456789abcdef0123456789abcdef"
	if _, err := adminDB.Exec("INSERT INTO `"+schema+"`.sshappy_traffic_batch (batch_id, node_id, created_at) VALUES (?, 116, 1)", markerID); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("DROP TABLE `" + schema + "`.sshappy_schema_migrations"); err != nil {
		t.Fatal(err)
	}

	if _, err := adminDB.Exec("DROP USER IF EXISTS '" + runtimeUser + "'@'%'"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("CREATE USER '" + runtimeUser + "'@'%' IDENTIFIED BY '" + runtimePassword + "'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP USER IF EXISTS '" + runtimeUser + "'@'%'"); err != nil {
			t.Errorf("drop runtime user: %v", err)
		}
	}()
	if _, err := adminDB.Exec("GRANT SELECT ON `" + schema + "`.* TO '" + runtimeUser + "'@'%'"); err != nil {
		t.Fatal(err)
	}

	legacyConfig := mysqlIntegrationConfig(t, driverConfig, schema, runtimeUser, runtimePassword, "auto")
	database, err = OpenDatabaseContext(t.Context(), legacyConfig)
	if err != nil {
		t.Fatalf("compatible 4.3 schema with a no-DDL account should start: %v", err)
	}
	if database.schemaState != databaseSchemaLegacyCompatible {
		t.Fatalf("schema state = %d, want legacy compatible", database.schemaState)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var markerCount int
	if err := adminDB.QueryRow("SELECT COUNT(*) FROM `"+schema+"`.sshappy_traffic_batch WHERE batch_id = ?", markerID).Scan(&markerCount); err != nil {
		t.Fatal(err)
	}
	if markerCount != 1 {
		t.Fatal("compatible 4.3 marker row was not preserved")
	}
	var migrationTables int
	if err := adminDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'sshappy_schema_migrations'
	`, schema).Scan(&migrationTables); err != nil {
		t.Fatal(err)
	}
	if migrationTables != 0 {
		t.Fatal("legacy-compatible startup unexpectedly executed DDL")
	}

	strictConfig := legacyConfig
	strictConfig.MySQLSchemaMode = "strict"
	database, err = OpenDatabaseContext(t.Context(), strictConfig)
	if database != nil {
		_ = database.Close()
	}
	if !errors.Is(err, ErrDatabaseMigrationRequired) {
		t.Fatalf("strict mode should require the migration record, got %v", err)
	}

	if _, err := adminDB.Exec("DROP TABLE `" + schema + "`.sshappy_traffic_batch"); err != nil {
		t.Fatal(err)
	}
	database, err = OpenDatabaseContext(t.Context(), legacyConfig)
	if database != nil {
		_ = database.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "automatic database schema initialization") {
		t.Fatalf("fresh schema with a no-DDL account should return an actionable error, got %v", err)
	}
	if strings.Contains(err.Error(), runtimePassword) {
		t.Fatal("database initialization error exposed the password")
	}

	const concurrentSchema = "sshappy_auto_concurrent_test"
	if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + concurrentSchema + "`"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE `" + concurrentSchema + "`"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + concurrentSchema + "`"); err != nil {
			t.Errorf("drop concurrent schema: %v", err)
		}
	}()
	concurrentConfig := mysqlIntegrationConfig(t, driverConfig, concurrentSchema, driverConfig.User, driverConfig.Passwd, "auto")
	type openResult struct {
		state databaseSchemaState
		err   error
	}
	const concurrentOpeners = 8
	start := make(chan struct{})
	results := make(chan openResult, concurrentOpeners)
	for range concurrentOpeners {
		go func() {
			<-start
			database, err := OpenDatabaseContext(t.Context(), concurrentConfig)
			if err != nil {
				results <- openResult{err: err}
				return
			}
			state := database.schemaState
			results <- openResult{state: state, err: database.Close()}
		}()
	}
	close(start)
	initialized := 0
	for range concurrentOpeners {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent automatic initialization failed: %v", result.err)
		}
		if result.state == databaseSchemaInitialized {
			initialized++
		}
	}
	if initialized != 1 {
		t.Fatalf("concurrent initializers reporting schema creation = %d, want 1", initialized)
	}
	if err := adminDB.QueryRow("SELECT COUNT(*) FROM `" + concurrentSchema + "`.sshappy_schema_migrations").Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 1 {
		t.Fatalf("concurrent migration records = %d, want 1", migrations)
	}

	const partialSchema = "sshappy_auto_partial_test"
	if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + partialSchema + "`"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE `" + partialSchema + "`"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + partialSchema + "`"); err != nil {
			t.Errorf("drop partial schema: %v", err)
		}
	}()
	partialDriverConfig := *driverConfig
	partialDriverConfig.DBName = partialSchema
	partialDB, err := sql.Open("mysql", partialDriverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	statements, err := embeddedMySQLMigrationStatements()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partialDB.Exec(statements[0]); err != nil {
		_ = partialDB.Close()
		t.Fatalf("create interrupted empty migration table: %v", err)
	}
	if err := partialDB.Close(); err != nil {
		t.Fatal(err)
	}
	partialConfig := mysqlIntegrationConfig(t, driverConfig, partialSchema, driverConfig.User, driverConfig.Passwd, "auto")
	database, err = OpenDatabaseContext(t.Context(), partialConfig)
	if err != nil {
		t.Fatalf("recover interrupted schema initialization: %v", err)
	}
	if database.schemaState != databaseSchemaInitialized {
		t.Fatalf("partial schema state = %d, want initialized", database.schemaState)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRow("SELECT COUNT(*) FROM `" + partialSchema + "`.sshappy_schema_migrations").Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 1 {
		t.Fatalf("recovered migration records = %d, want 1", migrations)
	}

	const viewSchema = "sshappy_auto_view_test"
	if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + viewSchema + "`"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE `" + viewSchema + "`"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP DATABASE IF EXISTS `" + viewSchema + "`"); err != nil {
			t.Errorf("drop view schema: %v", err)
		}
	}()
	if _, err := adminDB.Exec("CREATE VIEW `" + viewSchema + "`.sshappy_traffic_batch AS SELECT REPEAT('0', 32) AS batch_id, 1 AS node_id, 1 AS created_at"); err != nil {
		t.Fatal(err)
	}
	viewConfig := mysqlIntegrationConfig(t, driverConfig, viewSchema, driverConfig.User, driverConfig.Passwd, "auto")
	database, err = OpenDatabaseContext(t.Context(), viewConfig)
	if database != nil {
		_ = database.Close()
	}
	if !errors.Is(err, ErrDatabaseMigrationRequired) {
		t.Fatalf("reserved traffic table name used by a view should fail closed, got %v", err)
	}
	if err := adminDB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'sshappy_schema_migrations'
	`, viewSchema).Scan(&migrationTables); err != nil {
		t.Fatal(err)
	}
	if migrationTables != 0 {
		t.Fatal("view collision unexpectedly created the other schema table")
	}
}

func TestMySQLChunkedTrafficRecoveryAndIdempotency(t *testing.T) {
	dsn := os.Getenv("SSHAPPY_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("SSHAPPY_TEST_MYSQL_DSN is not set")
	}
	driverConfig, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	driverConfig.MultiStatements = true
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetTables := func() {
		for _, table := range []string{
			"sshappy_schema_migrations",
			"sshappy_traffic_batch",
			"sshappy_traffic_batch_43_backup",
			"user_traffic_log",
			"user",
			"ss_node",
		} {
			if _, err := db.Exec("DROP TABLE IF EXISTS `" + table + "`"); err != nil {
				t.Errorf("drop disposable integration table %s: %v", table, err)
			}
		}
	}
	resetTables()
	defer resetTables()
	if _, err := db.Exec(`
		CREATE TABLE sshappy_traffic_batch (
			batch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
			node_id INT NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (batch_id),
			KEY node_created_at (node_id, created_at)
		) ENGINE=InnoDB
	`); err != nil {
		t.Fatalf("create existing 4.3 traffic batch table: %v", err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", mysqlMigrationPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	var schema string
	if err := db.QueryRow("SELECT DATABASE()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if err := validateDatabaseSchemaContext(t.Context(), db, schema); err != nil {
		t.Fatalf("validate migrated schema: %v", err)
	}
	assertMySQLRuntimeSchemaValidationIsReadOnly(t, db, driverConfig)
	for _, statement := range []string{
		"CREATE TABLE user (id INT PRIMARY KEY, u BIGINT NOT NULL DEFAULT 0, d BIGINT NOT NULL DEFAULT 0, t BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE user_traffic_log (user_id INT, u BIGINT, d BIGINT, node_id INT, rate DOUBLE, traffic VARCHAR(32), log_time BIGINT) ENGINE=InnoDB",
		"CREATE TABLE ss_node (id INT PRIMARY KEY, node_heartbeat BIGINT NOT NULL DEFAULT 0, node_bandwidth BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"INSERT INTO ss_node (id) VALUES (116)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	traffic := make([]TrafficDelta, 120)
	billed := make([]billedTrafficDelta, 120)
	for index := range traffic {
		userID := index + 1
		if _, err := db.Exec("INSERT INTO user (id) VALUES (?)", userID); err != nil {
			t.Fatal(err)
		}
		traffic[index] = TrafficDelta{UserID: userID, Upload: 10, Download: 20}
		billed[index] = billedTrafficDelta{
			TrafficDelta:   traffic[index],
			BilledUpload:   10,
			BilledDownload: 20,
			TrafficText:    "30.00B",
		}
	}
	lockDB, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer lockDB.Close()
	database := &Database{db: db, lockDB: lockDB, config: Config{MySQLIOTimeoutSeconds: 5}}
	node := Node{ID: 116, TrafficRate: 1}
	assertMySQLCanceledTrafficReleasesLock(t, db, database, node, traffic[0])
	batchID := "0123456789abcdef0123456789abcdef"
	partialConn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.reportTrafficChunkContext(t.Context(), partialConn, node, trafficChunkID(batchID, node.ID, 0), billed[:trafficSQLBatchSize], time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := partialConn.Close(); err != nil {
		t.Fatal(err)
	}

	var waitGroup sync.WaitGroup
	errors := make(chan error, 4)
	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errors <- database.ReportTraffic(node, batchID, traffic)
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	var upload, download, logs, nodeBandwidth, markers int64
	if err := db.QueryRow("SELECT SUM(u), SUM(d) FROM user").Scan(&upload, &download); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM user_traffic_log").Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT node_bandwidth FROM ss_node WHERE id = 116").Scan(&nodeBandwidth); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sshappy_traffic_batch").Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if upload != 1200 || download != 2400 || logs != 120 || nodeBandwidth != 3600 || markers != 1 {
		t.Fatalf("upload=%d download=%d logs=%d nodeBandwidth=%d markers=%d", upload, download, logs, nodeBandwidth, markers)
	}
}

func assertMySQLCanceledTrafficReleasesLock(t *testing.T, adminDB *sql.DB, database *Database, node Node, traffic TrafficDelta) {
	t.Helper()
	blocker, err := adminDB.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err := blocker.ExecContext(t.Context(), "LOCK TABLES user WRITE"); err != nil {
		t.Fatalf("lock user table: %v", err)
	}
	unlocked := false
	defer func() {
		if !unlocked {
			if _, err := blocker.ExecContext(context.Background(), "UNLOCK TABLES"); err != nil {
				t.Errorf("unlock user table: %v", err)
			}
		}
	}()

	const batchID = "fedcba9876543210fedcba9876543210"
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	err = database.ReportTrafficContext(ctx, node, batchID, []TrafficDelta{traffic})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked traffic report should reach its deadline, got %v", err)
	}

	lockCheckCtx, lockCheckCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer lockCheckCancel()
	lockCheckConn, err := adminDB.Conn(lockCheckCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer lockCheckConn.Close()
	lockName := trafficBatchLockName(node.ID, batchID)
	var acquired sql.NullInt64
	if err := lockCheckConn.QueryRowContext(lockCheckCtx, "SELECT GET_LOCK(?, 2)", lockName).Scan(&acquired); err != nil {
		t.Fatalf("acquire advisory lock after canceled traffic report: %v", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		t.Fatal("canceled traffic report leaked its advisory lock")
	}
	var released sql.NullInt64
	if err := lockCheckConn.QueryRowContext(lockCheckCtx, "SELECT RELEASE_LOCK(?)", lockName).Scan(&released); err != nil {
		t.Fatalf("release advisory lock check: %v", err)
	}
	if !released.Valid || released.Int64 != 1 {
		t.Fatal("advisory lock check was not owned at release")
	}

	if _, err := blocker.ExecContext(t.Context(), "UNLOCK TABLES"); err != nil {
		t.Fatalf("unlock user table: %v", err)
	}
	unlocked = true
	var markers int
	if err := adminDB.QueryRowContext(t.Context(), `
		SELECT COUNT(*)
		FROM sshappy_traffic_batch
		WHERE batch_id = ? OR batch_id = ?
	`, batchID, trafficChunkID(batchID, node.ID, 0)).Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if markers != 0 {
		t.Fatalf("canceled traffic report left %d committed marker(s)", markers)
	}
}

func mysqlIntegrationConfig(
	t *testing.T,
	driverConfig *mysql.Config,
	schema, user, password, schemaMode string,
) Config {
	t.Helper()
	if driverConfig.Net != "tcp" {
		t.Skipf("MySQL schema integration requires TCP, got %q", driverConfig.Net)
	}
	host, portString, err := net.SplitHostPort(driverConfig.Addr)
	if err != nil {
		t.Fatalf("parse MySQL test address: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("parse MySQL test port: %v", err)
	}
	return Config{
		MySQLHost:                  host,
		MySQLPort:                  port,
		MySQLDB:                    schema,
		MySQLUser:                  user,
		MySQLPassword:              password,
		MySQLTLSMode:               "disabled",
		MySQLSchemaMode:            schemaMode,
		MySQLConnectTimeoutSeconds: 5,
		MySQLIOTimeoutSeconds:      5,
	}
}

func assertMySQLRuntimeSchemaValidationIsReadOnly(t *testing.T, adminDB *sql.DB, driverConfig *mysql.Config) {
	t.Helper()
	if driverConfig.Net != "tcp" {
		t.Logf("skip least-privilege startup check for MySQL network %q", driverConfig.Net)
		return
	}
	host, portString, err := net.SplitHostPort(driverConfig.Addr)
	if err != nil {
		t.Fatalf("parse MySQL test address: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("parse MySQL test port: %v", err)
	}

	const (
		runtimeUser     = "sshappy_runtime_validator"
		runtimePassword = "runtime-test-password"
	)
	if _, err := adminDB.Exec("DROP USER IF EXISTS 'sshappy_runtime_validator'@'%'"); err != nil {
		t.Fatalf("remove stale runtime test user: %v", err)
	}
	if _, err := adminDB.Exec("CREATE USER 'sshappy_runtime_validator'@'%' IDENTIFIED BY 'runtime-test-password'"); err != nil {
		t.Fatalf("create runtime test user: %v", err)
	}
	defer func() {
		if _, err := adminDB.Exec("DROP USER IF EXISTS 'sshappy_runtime_validator'@'%'"); err != nil {
			t.Errorf("remove runtime test user: %v", err)
		}
	}()
	if _, err := adminDB.Exec("GRANT SELECT ON *.* TO 'sshappy_runtime_validator'@'%'"); err != nil {
		t.Fatalf("grant runtime test privileges: %v", err)
	}

	runtimeConfig := Config{
		MySQLHost:                  host,
		MySQLPort:                  port,
		MySQLDB:                    driverConfig.DBName,
		MySQLUser:                  runtimeUser,
		MySQLPassword:              runtimePassword,
		MySQLTLSMode:               "disabled",
		MySQLConnectTimeoutSeconds: 5,
		MySQLIOTimeoutSeconds:      5,
	}
	database, err := OpenDatabaseContext(t.Context(), runtimeConfig)
	if err != nil {
		t.Fatalf("open migrated schema with read-only runtime account: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := adminDB.Exec("RENAME TABLE sshappy_traffic_batch TO sshappy_traffic_batch_43_backup"); err != nil {
		t.Fatalf("temporarily hide traffic batch table: %v", err)
	}
	restored := false
	defer func() {
		if !restored {
			if _, err := adminDB.Exec("RENAME TABLE sshappy_traffic_batch_43_backup TO sshappy_traffic_batch"); err != nil {
				t.Errorf("restore traffic batch table: %v", err)
			}
		}
	}()
	database, err = OpenDatabaseContext(t.Context(), runtimeConfig)
	if database != nil {
		_ = database.Close()
	}
	if !errors.Is(err, ErrDatabaseMigrationRequired) {
		t.Fatalf("missing table should require a migration, got %v", err)
	}
	var unexpectedTable int
	if err := adminDB.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'sshappy_traffic_batch'
	`, driverConfig.DBName).Scan(&unexpectedTable); err != nil {
		t.Fatal(err)
	}
	if unexpectedTable != 0 {
		t.Fatal("runtime startup unexpectedly recreated the missing traffic batch table")
	}
	if _, err := adminDB.Exec("RENAME TABLE sshappy_traffic_batch_43_backup TO sshappy_traffic_batch"); err != nil {
		t.Fatalf("restore traffic batch table: %v", err)
	}
	restored = true
}
