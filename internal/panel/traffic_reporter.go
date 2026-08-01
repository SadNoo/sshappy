package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	trafficOutboxSchemaVersion = 1
	trafficOutboxApplicationID = 0x53534850 // "SSHP"
	trafficOutboxBusyTimeoutMS = 5000
	createTrafficBatchesSQL    = `CREATE TABLE traffic_batches (
			sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK(sequence > 0),
            batch_id TEXT NOT NULL UNIQUE CHECK(length(batch_id) = 32),
            created_at INTEGER NOT NULL CHECK(created_at > 0),
            node_id INTEGER NOT NULL CHECK(node_id > 0),
            traffic_rate TEXT NOT NULL CHECK(length(traffic_rate) > 0),
            payload_sha256 BLOB NOT NULL CHECK(length(payload_sha256) = 32)
        ) STRICT`
	createTrafficDeltasSQL = `CREATE TABLE traffic_deltas (
            batch_sequence INTEGER NOT NULL REFERENCES traffic_batches(sequence) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
            user_id INTEGER NOT NULL CHECK(user_id > 0),
            upload INTEGER NOT NULL CHECK(upload >= 0),
            download INTEGER NOT NULL CHECK(download >= 0),
            PRIMARY KEY(batch_sequence, ordinal),
            UNIQUE(batch_sequence, user_id),
            CHECK(upload > 0 OR download > 0)
        ) STRICT`
)

var (
	errTrafficOutboxPersistence       = errors.New("traffic outbox persistence failed")
	errTrafficOutboxPartialInitMarker = errors.New("partial traffic outbox initialization marker")
)

var trafficOutboxSidecarSuffixes = [...]string{"-wal", "-shm", "-journal"}

const trafficOutboxInitMarkerContent = "sshappy-traffic-outbox-init-v1\n"

type trafficDatabase interface {
	ReportTraffic(node Node, batchID string, traffic []TrafficDelta) error
}

type contextualTrafficDatabase interface {
	ReportTrafficContext(ctx context.Context, node Node, batchID string, traffic []TrafficDelta) error
}

type trafficOutboxProcessLock interface {
	Validate() error
	Close() error
}

type trafficOutboxMetrics struct {
	Batches        int
	Users          int
	Records        int
	UploadBytes    int64
	DownloadBytes  int64
	FileBytes      int64
	OldestAge      time.Duration
	DiskAvailable  bool
	DiskFreeBytes  uint64
	DiskTotalBytes uint64
}

// trafficReporter is a single-writer durable queue. The mutex serializes the
// in-process writer and the sql.DB is restricted to one connection so all
// connection-scoped safety PRAGMAs apply to every operation.
type trafficReporter struct {
	mu          sync.Mutex
	path        string
	db          *sql.DB
	pending     int
	fileBytes   int64
	mainFile    os.FileInfo
	dirFile     os.FileInfo
	processLock trafficOutboxProcessLock
	poisoned    error
	closed      bool
}

func newTrafficReporter(path string) (*trafficReporter, error) {
	return newTrafficReporterContext(context.Background(), path)
}

func newTrafficReporterContext(ctx context.Context, path string) (_ *trafficReporter, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("traffic outbox path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve traffic outbox path: %w", err)
	}
	absPath, err = resolveTrafficOutboxPath(absPath)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateTrafficOutboxDirectory(filepath.Dir(absPath)); err != nil {
		return nil, err
	}
	processLock, err := acquireTrafficOutboxProcessLock(absPath + ".lock")
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = processLock.Close()
		}
	}()
	needsInitialization, initInProgress, err := prepareTrafficOutboxPath(absPath)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", trafficOutboxDSN(absPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite traffic outbox: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	reporter := &trafficReporter{path: absPath, db: db, processLock: processLock}
	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite traffic outbox: %w", err)
	}
	if needsInitialization {
		if err := configureTrafficOutboxSQLite(ctx, db); err != nil {
			return nil, err
		}
		if err := initializeTrafficOutboxSchema(ctx, db); err != nil {
			return nil, err
		}
	} else {
		uninitialized, err := trafficOutboxIsSafelyUninitialized(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect SQLite traffic outbox initialization state: %w", err)
		}
		if uninitialized {
			if !initInProgress {
				return nil, fmt.Errorf("invalid SQLite traffic outbox at %q; uninitialized database has no sshappy initialization marker and was preserved", absPath)
			}
			if err := configureTrafficOutboxSQLite(ctx, db); err != nil {
				return nil, err
			}
			if err := initializeTrafficOutboxSchema(ctx, db); err != nil {
				return nil, err
			}
		} else {
			if err := verifyTrafficOutboxSchema(ctx, db); err != nil {
				return nil, fmt.Errorf("invalid SQLite traffic outbox at %q; preserve and move it manually after reconciliation: %w", absPath, err)
			}
			if err := configureTrafficOutboxSQLite(ctx, db); err != nil {
				return nil, err
			}
		}
	}
	if err := verifyTrafficOutboxPragmas(ctx, db); err != nil {
		return nil, err
	}
	if err := secureTrafficOutboxFiles(absPath); err != nil {
		return nil, err
	}
	reporter.mainFile, err = os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat SQLite traffic outbox: %w", err)
	}
	reporter.dirFile, err = os.Lstat(filepath.Dir(absPath))
	if err != nil {
		return nil, fmt.Errorf("failed to stat traffic outbox directory: %w", err)
	}
	reporter.pending, err = validateAndCountTrafficBatches(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to read SQLite traffic outbox: %w", err)
	}
	if initInProgress {
		if err := removeTrafficOutboxInitMarker(absPath); err != nil {
			return nil, err
		}
	}
	reporter.refreshFileBytesBestEffort()
	return reporter, nil
}

func trafficOutboxIsSafelyUninitialized(ctx context.Context, db *sql.DB) (bool, error) {
	var applicationID, version, objects int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return false, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return false, err
	}
	if applicationID != 0 || version != 0 {
		return false, nil
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'view', 'trigger')`).Scan(&objects); err != nil {
		return false, err
	}
	return objects == 0, nil
}

func trafficOutboxDSN(path string) string {
	query := make(url.Values)
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", trafficOutboxBusyTimeoutMS))
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	return (&url.URL{Scheme: "file", Path: path, RawQuery: query.Encode()}).String()
}

func configureTrafficOutboxSQLite(ctx context.Context, db *sql.DB) error {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return fmt.Errorf("failed to enable SQLite WAL mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("failed to enable SQLite WAL mode: got %q", mode)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("failed to enable SQLite FULL synchronization: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("failed to enable SQLite foreign keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", trafficOutboxBusyTimeoutMS)); err != nil {
		return fmt.Errorf("failed to configure SQLite busy timeout: %w", err)
	}
	return nil
}

func verifyTrafficOutboxPragmas(ctx context.Context, db *sql.DB) error {
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || !strings.EqualFold(journal, "wal") {
		return fmt.Errorf("SQLite traffic outbox journal_mode must be WAL: value=%q err=%v", journal, err)
	}
	checks := []struct {
		name string
		want int
	}{
		{name: "synchronous", want: 2},
		{name: "foreign_keys", want: 1},
		{name: "busy_timeout", want: trafficOutboxBusyTimeoutMS},
	}
	for _, check := range checks {
		var got int
		if err := db.QueryRowContext(ctx, "PRAGMA "+check.name).Scan(&got); err != nil {
			return fmt.Errorf("failed to verify SQLite %s: %w", check.name, err)
		}
		if got != check.want {
			return fmt.Errorf("SQLite %s=%d, want %d", check.name, got, check.want)
		}
	}
	return nil
}

func initializeTrafficOutboxSchema(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin SQLite traffic outbox initialization: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		createTrafficBatchesSQL,
		createTrafficDeltasSQL,
		fmt.Sprintf("PRAGMA application_id=%d", trafficOutboxApplicationID),
		fmt.Sprintf("PRAGMA user_version=%d", trafficOutboxSchemaVersion),
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("failed to initialize SQLite traffic outbox schema: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit SQLite traffic outbox schema: %w", err)
	}
	return verifyTrafficOutboxSchema(ctx, db)
}

func verifyTrafficOutboxSchema(ctx context.Context, db *sql.DB) error {
	var applicationID, version int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return fmt.Errorf("failed to read SQLite application ID: %w", err)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("failed to read SQLite schema version: %w", err)
	}
	if applicationID != trafficOutboxApplicationID {
		return fmt.Errorf("unexpected SQLite application ID %d", applicationID)
	}
	if version != trafficOutboxSchemaVersion {
		return fmt.Errorf("unsupported SQLite traffic outbox schema version %d", version)
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("SQLite integrity check failed: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("SQLite integrity check failed: %s", integrity)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("SQLite foreign key check failed: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("SQLite foreign key check found an invalid row")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("SQLite foreign key check failed: %w", err)
	}
	var tables int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('traffic_batches','traffic_deltas')`).Scan(&tables); err != nil {
		return fmt.Errorf("failed to inspect SQLite traffic outbox schema: %w", err)
	}
	if tables != 2 {
		return fmt.Errorf("SQLite traffic outbox schema is incomplete: found %d required tables", tables)
	}
	var applicationObjects int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").Scan(&applicationObjects); err != nil {
		return fmt.Errorf("failed to count SQLite traffic outbox schema objects: %w", err)
	}
	if applicationObjects != 2 {
		return fmt.Errorf("SQLite traffic outbox has %d application schema objects, want 2", applicationObjects)
	}
	if err := verifyTrafficOutboxTable(ctx, db, "traffic_batches", createTrafficBatchesSQL, []sqliteColumn{
		{name: "sequence", typ: "INTEGER", primaryKey: 1},
		{name: "batch_id", typ: "TEXT", notNull: 1},
		{name: "created_at", typ: "INTEGER", notNull: 1},
		{name: "node_id", typ: "INTEGER", notNull: 1},
		{name: "traffic_rate", typ: "TEXT", notNull: 1},
		{name: "payload_sha256", typ: "BLOB", notNull: 1},
	}, [][]string{{"batch_id"}}); err != nil {
		return err
	}
	if err := verifyTrafficOutboxTable(ctx, db, "traffic_deltas", createTrafficDeltasSQL, []sqliteColumn{
		{name: "batch_sequence", typ: "INTEGER", notNull: 1, primaryKey: 1},
		{name: "ordinal", typ: "INTEGER", notNull: 1, primaryKey: 2},
		{name: "user_id", typ: "INTEGER", notNull: 1},
		{name: "upload", typ: "INTEGER", notNull: 1},
		{name: "download", typ: "INTEGER", notNull: 1},
	}, [][]string{{"batch_sequence", "ordinal"}, {"batch_sequence", "user_id"}}); err != nil {
		return err
	}
	if err := verifyTrafficOutboxForeignKey(ctx, db); err != nil {
		return err
	}
	return nil
}

type sqliteColumn struct {
	name       string
	typ        string
	notNull    int
	primaryKey int
}

func verifyTrafficOutboxTable(ctx context.Context, db *sql.DB, table, expectedSQL string, expectedColumns []sqliteColumn, expectedUniqueIndexes [][]string) error {
	var schemaSQL string
	if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&schemaSQL); err != nil {
		return fmt.Errorf("failed to read SQLite schema for %s: %w", table, err)
	}
	if normalizeSQLiteSchema(schemaSQL) != normalizeSQLiteSchema(expectedSQL) {
		return fmt.Errorf("SQLite table %s definition does not match schema version %d", table, trafficOutboxSchemaVersion)
	}
	var schemaName, tableName, objectType string
	var columns, withoutRowID, strict int
	if err := db.QueryRowContext(ctx, "PRAGMA table_list("+quoteSQLiteIdentifier(table)+")").Scan(&schemaName, &tableName, &objectType, &columns, &withoutRowID, &strict); err != nil {
		return fmt.Errorf("failed to inspect SQLite table %s: %w", table, err)
	}
	if schemaName != "main" || tableName != table || objectType != "table" || columns != len(expectedColumns) || withoutRowID != 0 || strict != 1 {
		return fmt.Errorf("SQLite table %s has unexpected table metadata", table)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA table_xinfo("+quoteSQLiteIdentifier(table)+")")
	if err != nil {
		return fmt.Errorf("failed to inspect SQLite columns for %s: %w", table, err)
	}
	var actual []sqliteColumn
	for rows.Next() {
		var cid, hidden int
		var column sqliteColumn
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &column.name, &column.typ, &column.notNull, &defaultValue, &column.primaryKey, &hidden); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read SQLite columns for %s: %w", table, err)
		}
		if cid != len(actual) || hidden != 0 || defaultValue.Valid {
			rows.Close()
			return fmt.Errorf("SQLite table %s column %s has unexpected metadata", table, column.name)
		}
		actual = append(actual, column)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close SQLite column inspection for %s: %w", table, err)
	}
	if len(actual) != len(expectedColumns) {
		return fmt.Errorf("SQLite table %s has %d columns, want %d", table, len(actual), len(expectedColumns))
	}
	for i := range expectedColumns {
		if actual[i] != expectedColumns[i] {
			return fmt.Errorf("SQLite table %s column %d differs from schema version %d", table, i, trafficOutboxSchemaVersion)
		}
	}
	return verifyTrafficOutboxIndexes(ctx, db, table, expectedUniqueIndexes)
}

func verifyTrafficOutboxIndexes(ctx context.Context, db *sql.DB, table string, expected [][]string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA index_list("+quoteSQLiteIdentifier(table)+")")
	if err != nil {
		return fmt.Errorf("failed to inspect SQLite indexes for %s: %w", table, err)
	}
	var uniqueIndexNames []string
	for rows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read SQLite indexes for %s: %w", table, err)
		}
		if unique == 1 && partial == 0 {
			uniqueIndexNames = append(uniqueIndexNames, name)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close SQLite index inspection for %s: %w", table, err)
	}
	var actual [][]string
	for _, indexName := range uniqueIndexNames {
		indexRows, err := db.QueryContext(ctx, "PRAGMA index_info("+quoteSQLiteIdentifier(indexName)+")")
		if err != nil {
			return fmt.Errorf("failed to inspect SQLite index %s: %w", indexName, err)
		}
		var columns []string
		for indexRows.Next() {
			var sequence, cid int
			var column string
			if err := indexRows.Scan(&sequence, &cid, &column); err != nil {
				indexRows.Close()
				return fmt.Errorf("failed to read SQLite index %s: %w", indexName, err)
			}
			if sequence != len(columns) || cid < 0 {
				indexRows.Close()
				return fmt.Errorf("SQLite index %s contains an unexpected expression", indexName)
			}
			columns = append(columns, column)
		}
		if err := indexRows.Close(); err != nil {
			return fmt.Errorf("failed to close SQLite index inspection for %s: %w", indexName, err)
		}
		actual = append(actual, columns)
	}
	if !equalStringSets(actual, expected) {
		return fmt.Errorf("SQLite table %s unique indexes differ from schema version %d: got %v want %v", table, trafficOutboxSchemaVersion, actual, expected)
	}
	return nil
}

func verifyTrafficOutboxForeignKey(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_list(traffic_deltas)")
	if err != nil {
		return fmt.Errorf("failed to inspect SQLite traffic outbox foreign key: %w", err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var id, sequence int
		var table, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return fmt.Errorf("failed to read SQLite traffic outbox foreign key: %w", err)
		}
		if id != 0 || sequence != 0 || table != "traffic_batches" || from != "batch_sequence" || to != "sequence" || onUpdate != "NO ACTION" || onDelete != "CASCADE" || match != "NONE" {
			return errors.New("SQLite traffic outbox foreign key differs from schema version 1")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to inspect SQLite traffic outbox foreign key: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("SQLite traffic outbox has %d foreign keys, want 1", count)
	}
	return nil
}

func normalizeSQLiteSchema(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func quoteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func equalStringSets(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, left := range a {
		matched := false
		for j, right := range b {
			if used[j] || len(left) != len(right) {
				continue
			}
			equal := true
			for i := range left {
				if left[i] != right[i] {
					equal = false
					break
				}
			}
			if equal {
				used[j] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (r *trafficReporter) Capture(node Node, deltas []TrafficDelta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.usableLocked(); err != nil {
		return err
	}
	if len(deltas) == 0 {
		return nil
	}
	if err := r.validateFilesLocked(); err != nil {
		return r.poisonLocked("traffic outbox file validation failed", err)
	}
	canonicalDeltas, err := canonicalTrafficDeltas(deltas)
	if err != nil {
		return r.poisonLocked("invalid captured traffic", err)
	}
	rateText, err := canonicalTrafficRate(node.TrafficRate)
	if err != nil || node.ID <= 0 {
		if err == nil {
			err = errors.New("node ID must be positive")
		}
		return r.poisonLocked("invalid captured billing context", err)
	}
	if _, err := prepareBilledTraffic(node.TrafficRate, canonicalDeltas); err != nil {
		return r.poisonLocked("captured traffic cannot be replayed safely", err)
	}
	id, err := newTrafficBatchID()
	if err != nil {
		return r.poisonLocked("failed to create traffic batch", err)
	}
	batch := TrafficBatch{
		ID:              id,
		CreatedAt:       time.Now().Unix(),
		NodeID:          node.ID,
		TrafficRateText: rateText,
		Deltas:          canonicalDeltas,
	}
	batch.PayloadSHA256 = trafficBatchSHA256(batch)
	if err := validateTrafficBatch(batch); err != nil {
		return r.poisonLocked("invalid captured traffic batch", err)
	}
	if err := insertTrafficBatch(context.Background(), r.db, batch); err != nil {
		return r.poisonLocked("failed to commit captured traffic", err)
	}
	r.pending++
	r.refreshFileBytesBestEffort()
	return nil
}

func insertTrafficBatch(ctx context.Context, db *sql.DB, batch TrafficBatch) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO traffic_batches
        (batch_id, created_at, node_id, traffic_rate, payload_sha256)
        VALUES (?, ?, ?, ?, ?)`, batch.ID, batch.CreatedAt, batch.NodeID, batch.TrafficRateText, batch.PayloadSHA256[:])
	if err != nil {
		return err
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return err
	}
	for ordinal, delta := range batch.Deltas {
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_deltas
            (batch_sequence, ordinal, user_id, upload, download) VALUES (?, ?, ?, ?, ?)`,
			sequence, ordinal, delta.UserID, delta.Upload, delta.Download); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *trafficReporter) Flush(db trafficDatabase) error {
	_, err := r.FlushContext(context.Background(), db, 0)
	return err
}

// FlushContext replays at most maxBatches durable batches. A non-positive
// limit drains until the queue is empty, the context is canceled, or an error
// occurs. Once the remote database confirms a batch, its local acknowledgement
// always completes with an independent context so cancellation cannot leave a
// successfully billed batch needlessly pending.
func (r *trafficReporter) FlushContext(ctx context.Context, db trafficDatabase, maxBatches int) (flushed int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.usableLocked(); err != nil {
		return 0, err
	}
	for r.pending > 0 {
		if maxBatches > 0 && flushed >= maxBatches {
			return flushed, nil
		}
		if err := ctx.Err(); err != nil {
			return flushed, err
		}
		if err := r.validateFilesLocked(); err != nil {
			return flushed, r.poisonLocked("traffic outbox file validation failed", err)
		}
		batches, err := loadTrafficBatches(ctx, r.db, "WHERE b.sequence = (SELECT MIN(sequence) FROM traffic_batches)", nil)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return flushed, ctxErr
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return flushed, err
			}
			return flushed, r.poisonLocked("failed to verify traffic batch before flush", err)
		}
		if len(batches) != 1 {
			return flushed, r.poisonLocked("failed to verify traffic batch before flush", errors.New("durable queue count differs from in-memory state"))
		}
		batch := batches[0]
		rate, err := parseCanonicalTrafficRate(batch.TrafficRateText)
		if err != nil {
			return flushed, r.poisonLocked("failed to verify frozen traffic rate", err)
		}
		node := Node{ID: batch.NodeID, TrafficRate: rate}
		if contextualDB, ok := db.(contextualTrafficDatabase); ok {
			err = contextualDB.ReportTrafficContext(ctx, node, batch.ID, batch.Deltas)
		} else {
			err = db.ReportTraffic(node, batch.ID, batch.Deltas)
		}
		if err != nil {
			return flushed, err
		}
		if err := r.deleteCommittedBatchLocked(batch); err != nil {
			return flushed, r.poisonLocked("failed to delete traffic batch after database commit", err)
		}
		r.pending--
		flushed++
		r.refreshFileBytesBestEffort()
	}
	return flushed, nil
}

func (r *trafficReporter) deleteCommittedBatchLocked(expected TrafficBatch) error {
	if err := r.validateFilesLocked(); err != nil {
		return fmt.Errorf("%w after database commit: %v", errTrafficOutboxPersistence, err)
	}
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w after database commit: %v", errTrafficOutboxPersistence, err)
	}
	defer tx.Rollback()
	batches, err := loadTrafficBatches(ctx, tx, "WHERE b.batch_id = ?", []any{expected.ID})
	if err != nil {
		return fmt.Errorf("%w after database commit: %v", errTrafficOutboxPersistence, err)
	}
	if len(batches) != 1 || batches[0].PayloadSHA256 != expected.PayloadSHA256 {
		return fmt.Errorf("%w after database commit: durable batch changed", errTrafficOutboxPersistence)
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM traffic_batches WHERE batch_id = ? AND payload_sha256 = ?", expected.ID, expected.PayloadSHA256[:])
	if err != nil {
		return fmt.Errorf("%w after database commit: %v", errTrafficOutboxPersistence, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return fmt.Errorf("%w after database commit: expected one deleted batch, got %d: %v", errTrafficOutboxPersistence, deleted, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w after database commit: %v", errTrafficOutboxPersistence, err)
	}
	return nil
}

type trafficBatchQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadTrafficBatches(ctx context.Context, queryer trafficBatchQueryer, where string, args []any) ([]TrafficBatch, error) {
	query := `SELECT b.sequence, b.batch_id, b.created_at, b.node_id, b.traffic_rate, b.payload_sha256,
        d.ordinal, d.user_id, d.upload, d.download
        FROM traffic_batches b
        LEFT JOIN traffic_deltas d ON d.batch_sequence = b.sequence ` + where + `
        ORDER BY b.sequence, d.ordinal`
	rows, err := queryer.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var batches []TrafficBatch
	var current *TrafficBatch
	var currentSequence int64
	for rows.Next() {
		var (
			sequence                          int64
			batchID, rateText                 string
			createdAt                         int64
			nodeID                            int
			hash                              []byte
			ordinal, userID, upload, download sql.NullInt64
		)
		if err := rows.Scan(&sequence, &batchID, &createdAt, &nodeID, &rateText, &hash, &ordinal, &userID, &upload, &download); err != nil {
			return nil, err
		}
		if current == nil || sequence != currentSequence {
			if current != nil {
				if err := validateAndVerifyTrafficBatch(*current); err != nil {
					return nil, err
				}
			}
			if len(hash) != sha256.Size {
				return nil, fmt.Errorf("batch %q has invalid SHA-256 length %d", batchID, len(hash))
			}
			batches = append(batches, TrafficBatch{ID: batchID, CreatedAt: createdAt, NodeID: nodeID, TrafficRateText: rateText})
			current = &batches[len(batches)-1]
			copy(current.PayloadSHA256[:], hash)
			currentSequence = sequence
		}
		if ordinal.Valid || userID.Valid || upload.Valid || download.Valid {
			if !ordinal.Valid || !userID.Valid || !upload.Valid || !download.Valid {
				return nil, fmt.Errorf("batch %q has a partial traffic delta", batchID)
			}
			if ordinal.Int64 != int64(len(current.Deltas)) {
				return nil, fmt.Errorf("batch %q has non-canonical delta ordinal %d", batchID, ordinal.Int64)
			}
			current.Deltas = append(current.Deltas, TrafficDelta{UserID: int(userID.Int64), Upload: upload.Int64, Download: download.Int64})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		if err := validateAndVerifyTrafficBatch(*current); err != nil {
			return nil, err
		}
	}
	return batches, nil
}

func validateAndCountTrafficBatches(ctx context.Context, db *sql.DB) (int, error) {
	var nonpositiveSequences int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM traffic_batches WHERE sequence <= 0").Scan(&nonpositiveSequences); err != nil {
		return 0, err
	}
	if nonpositiveSequences != 0 {
		return 0, fmt.Errorf("traffic outbox contains %d non-positive batch sequence(s)", nonpositiveSequences)
	}
	var count int
	var previousSequence int64
	for {
		var sequence int64
		err := db.QueryRowContext(ctx, "SELECT sequence FROM traffic_batches WHERE sequence > ? ORDER BY sequence LIMIT 1", previousSequence).Scan(&sequence)
		if errors.Is(err, sql.ErrNoRows) {
			return count, nil
		}
		if err != nil {
			return 0, err
		}
		batches, err := loadTrafficBatches(ctx, db, "WHERE b.sequence = ?", []any{sequence})
		if err != nil {
			return 0, err
		}
		if len(batches) != 1 {
			return 0, fmt.Errorf("traffic batch sequence %d could not be read", sequence)
		}
		count++
		previousSequence = sequence
	}
}

func validateAndVerifyTrafficBatch(batch TrafficBatch) error {
	if err := validateTrafficBatch(batch); err != nil {
		return fmt.Errorf("invalid traffic batch %q: %w", batch.ID, err)
	}
	want := trafficBatchSHA256(batch)
	if subtle.ConstantTimeCompare(want[:], batch.PayloadSHA256[:]) != 1 {
		return fmt.Errorf("traffic batch %q payload SHA-256 mismatch", batch.ID)
	}
	return nil
}

func validateTrafficBatch(batch TrafficBatch) error {
	decodedID, err := hex.DecodeString(batch.ID)
	if err != nil || len(decodedID) != 16 || batch.ID != strings.ToLower(batch.ID) {
		return errors.New("batch ID must be 32 lowercase hexadecimal characters")
	}
	if batch.CreatedAt <= 0 || batch.NodeID <= 0 || len(batch.Deltas) == 0 {
		return errors.New("missing creation time, node ID, or traffic deltas")
	}
	rate, err := parseCanonicalTrafficRate(batch.TrafficRateText)
	if err != nil {
		return err
	}
	lastUserID := 0
	for _, delta := range batch.Deltas {
		if delta.UserID <= lastUserID || delta.Upload < 0 || delta.Download < 0 || delta.Upload == 0 && delta.Download == 0 {
			return fmt.Errorf("invalid or non-canonical traffic delta for user %d", delta.UserID)
		}
		lastUserID = delta.UserID
	}
	if _, err := prepareBilledTraffic(rate, batch.Deltas); err != nil {
		return fmt.Errorf("traffic batch cannot be replayed safely: %w", err)
	}
	return nil
}

func canonicalTrafficDeltas(deltas []TrafficDelta) ([]TrafficDelta, error) {
	merged := make(map[int]TrafficDelta, len(deltas))
	for _, delta := range deltas {
		if delta.UserID <= 0 || delta.Upload < 0 || delta.Download < 0 || delta.Upload == 0 && delta.Download == 0 {
			return nil, fmt.Errorf("invalid traffic delta for user %d", delta.UserID)
		}
		current := merged[delta.UserID]
		if delta.Upload > math.MaxInt64-current.Upload || delta.Download > math.MaxInt64-current.Download {
			return nil, fmt.Errorf("traffic delta overflow for user %d", delta.UserID)
		}
		current.UserID = delta.UserID
		current.Upload += delta.Upload
		current.Download += delta.Download
		merged[delta.UserID] = current
	}
	out := make([]TrafficDelta, 0, len(merged))
	for _, delta := range merged {
		out = append(out, delta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}

func canonicalTrafficRate(rate float64) (string, error) {
	if rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
		return "", errors.New("traffic rate must be a finite non-negative number")
	}
	if rate == 0 {
		rate = 0 // Normalize negative zero.
	}
	return strconv.FormatFloat(rate, 'g', -1, 64), nil
}

func parseCanonicalTrafficRate(text string) (float64, error) {
	rate, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, errors.New("traffic rate is not a valid float64")
	}
	canonical, err := canonicalTrafficRate(rate)
	if err != nil || canonical != text {
		return 0, errors.New("traffic rate text is not canonical")
	}
	return rate, nil
}

func trafficBatchSHA256(batch TrafficBatch) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("sshappy-traffic-outbox-batch-v1"))
	writeCanonicalString(h, batch.ID)
	writeCanonicalUint64(h, uint64(batch.CreatedAt))
	writeCanonicalUint64(h, uint64(batch.NodeID))
	writeCanonicalString(h, batch.TrafficRateText)
	writeCanonicalUint64(h, uint64(len(batch.Deltas)))
	for _, delta := range batch.Deltas {
		writeCanonicalUint64(h, uint64(delta.UserID))
		writeCanonicalUint64(h, uint64(delta.Upload))
		writeCanonicalUint64(h, uint64(delta.Download))
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func writeCanonicalString(writer io.Writer, value string) {
	writeCanonicalUint64(writer, uint64(len(value)))
	_, _ = io.WriteString(writer, value)
}

func writeCanonicalUint64(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func (r *trafficReporter) PendingBatches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

func (r *trafficReporter) PendingUsers() int {
	return r.Metrics(time.Now()).Users
}

func (r *trafficReporter) Metrics(now time.Time) trafficOutboxMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshFileBytesBestEffort()
	metrics := trafficOutboxMetrics{Batches: r.pending, FileBytes: r.fileBytes}
	if r.db != nil && !r.closed {
		if err := r.validateFilesLocked(); err != nil {
			_ = r.poisonLocked("traffic outbox file validation failed while reading metrics", err)
			return metrics
		}
		var oldest int64
		err := r.db.QueryRow(`SELECT
            COUNT(d.ordinal), COUNT(DISTINCT d.user_id),
            COALESCE(SUM(d.upload), 0), COALESCE(SUM(d.download), 0),
            COALESCE(MIN(b.created_at), 0)
            FROM traffic_batches b
            LEFT JOIN traffic_deltas d ON d.batch_sequence = b.sequence`).Scan(
			&metrics.Records, &metrics.Users, &metrics.UploadBytes, &metrics.DownloadBytes, &oldest,
		)
		if err != nil {
			_ = r.poisonLocked("failed to read traffic outbox metrics", err)
		} else if oldest > 0 {
			createdAt := time.Unix(oldest, 0)
			if !createdAt.After(now) {
				metrics.OldestAge = now.Sub(createdAt)
			}
		}
	}
	if disk, err := readDiskSpace(filepath.Dir(r.path)); err == nil {
		metrics.DiskAvailable = true
		metrics.DiskFreeBytes = disk.FreeBytes
		metrics.DiskTotalBytes = disk.TotalBytes
	}
	return metrics
}

func (r *trafficReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.db == nil {
		var lockErr error
		if r.processLock != nil {
			lockErr = r.processLock.Close()
			r.processLock = nil
		}
		return errors.Join(r.poisoned, lockErr)
	}
	var checkpointErr error
	if r.poisoned == nil {
		if err := r.validateFilesLocked(); err != nil {
			r.poisoned = fmt.Errorf("%w: traffic outbox file validation failed while closing: %v", errTrafficOutboxPersistence, err)
		}
	}
	if r.poisoned == nil {
		var busy, logFrames, checkpointed int
		if err := r.db.QueryRow("PRAGMA wal_checkpoint(FULL)").Scan(&busy, &logFrames, &checkpointed); err != nil {
			checkpointErr = fmt.Errorf("failed to checkpoint SQLite traffic outbox: %w", err)
		} else if busy != 0 {
			checkpointErr = fmt.Errorf("failed to checkpoint SQLite traffic outbox: %d busy frames", busy)
		}
	}
	closeErr := r.db.Close()
	var lockErr error
	if r.processLock != nil {
		lockErr = r.processLock.Close()
		r.processLock = nil
	}
	if r.poisoned != nil {
		return errors.Join(r.poisoned, checkpointErr, closeErr, lockErr)
	}
	if checkpointErr != nil || closeErr != nil || lockErr != nil {
		return fmt.Errorf("%w while closing: %v", errTrafficOutboxPersistence, errors.Join(checkpointErr, closeErr, lockErr))
	}
	return nil
}

func (r *trafficReporter) usableLocked() error {
	if r.poisoned != nil {
		return r.poisoned
	}
	if r.closed {
		return fmt.Errorf("%w: traffic outbox is closed", errTrafficOutboxPersistence)
	}
	if r.db == nil {
		return r.poisonLocked("traffic outbox is not initialized", errors.New("missing SQLite database"))
	}
	if r.processLock == nil {
		return r.poisonLocked("traffic outbox process lock is missing", errors.New("missing process lock"))
	}
	if err := r.processLock.Validate(); err != nil {
		return r.poisonLocked("traffic outbox process lock validation failed", err)
	}
	return nil
}

func (r *trafficReporter) poisonLocked(operation string, err error) error {
	if r.poisoned == nil {
		r.poisoned = fmt.Errorf("%w: %s: %v", errTrafficOutboxPersistence, operation, err)
	}
	return r.poisoned
}

func (r *trafficReporter) validateFilesLocked() error {
	if r.processLock == nil {
		return errors.New("traffic outbox process lock is missing")
	}
	if err := r.processLock.Validate(); err != nil {
		return err
	}
	return validatePrivateTrafficOutboxFiles(r.path, r.dirFile, r.mainFile)
}

func (r *trafficReporter) refreshFileBytesBestEffort() {
	if size, err := trafficOutboxFilesSize(r.path); err == nil {
		r.fileBytes = size
	}
}

func prepareTrafficOutboxPath(path string) (needsInitialization, initInProgress bool, retErr error) {
	dir := filepath.Dir(path)
	info, pathErr := os.Lstat(path)
	initInProgress, err := trafficOutboxInitMarkerExists(path)
	if err != nil {
		recoverableMain := errors.Is(pathErr, os.ErrNotExist) ||
			(pathErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() == 0)
		if !errors.Is(err, errTrafficOutboxPartialInitMarker) || !recoverableMain {
			return false, false, err
		}
		if sidecarErr := requireNoTrafficOutboxSidecars(path); sidecarErr != nil {
			return false, false, fmt.Errorf("cannot recover %w: %v", err, sidecarErr)
		}
		if pathErr == nil {
			if secureErr := secureTrafficOutboxFiles(path); secureErr != nil {
				return false, false, secureErr
			}
		}
		if repairErr := repairPartialTrafficOutboxInitMarker(path); repairErr != nil {
			return false, false, fmt.Errorf("failed to recover %w: %v", err, repairErr)
		}
		initInProgress = true
	}
	if errors.Is(pathErr, os.ErrNotExist) {
		if err := requireNoTrafficOutboxSidecars(path); err != nil {
			return false, initInProgress, err
		}
		if !initInProgress {
			if err := createTrafficOutboxInitMarker(path); err != nil {
				return false, false, err
			}
			initInProgress = true
		}
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr != nil {
			return false, initInProgress, fmt.Errorf("failed to create SQLite traffic outbox: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return false, initInProgress, fmt.Errorf("failed to close new SQLite traffic outbox: %w", closeErr)
		}
		if err := syncTrafficOutboxDirectory(dir); err != nil {
			return false, initInProgress, err
		}
		return true, initInProgress, nil
	}
	if pathErr != nil {
		return false, initInProgress, fmt.Errorf("failed to inspect traffic outbox: %w", pathErr)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, initInProgress, fmt.Errorf("traffic outbox %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return false, initInProgress, fmt.Errorf("traffic outbox %q must be a regular file", path)
	}
	if info.Size() == 0 {
		if !initInProgress {
			return false, false, fmt.Errorf("traffic outbox %q is empty and has no sshappy initialization marker; existing file was preserved", path)
		}
		if err := requireNoTrafficOutboxSidecars(path); err != nil {
			return false, true, fmt.Errorf("empty traffic outbox %q cannot be recovered: %w", path, err)
		}
		if err := secureTrafficOutboxFiles(path); err != nil {
			return false, true, err
		}
		return true, true, nil
	}
	header := make([]byte, 16)
	file, err := os.Open(path)
	if err != nil {
		return false, initInProgress, fmt.Errorf("failed to inspect traffic outbox format: %w", err)
	}
	_, readErr := io.ReadFull(file, header)
	closeErr := file.Close()
	if readErr != nil || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		return false, initInProgress, fmt.Errorf("traffic outbox %q is not SQLite; existing file was preserved and must be moved or reconciled manually before startup", path)
	}
	if closeErr != nil {
		return false, initInProgress, fmt.Errorf("failed to close traffic outbox while checking format: %w", closeErr)
	}
	if err := secureTrafficOutboxFiles(path); err != nil {
		return false, initInProgress, err
	}
	return false, initInProgress, nil
}

func requireNoTrafficOutboxSidecars(path string) error {
	for _, suffix := range trafficOutboxSidecarSuffixes {
		if _, err := os.Lstat(path + suffix); err == nil {
			return fmt.Errorf("orphaned SQLite traffic outbox sidecar %q must be reconciled manually", path+suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to inspect SQLite traffic outbox sidecar %q: %w", path+suffix, err)
		}
	}
	return nil
}

func trafficOutboxInitMarkerExists(path string) (bool, error) {
	markerPath := path + ".init"
	expected := []byte(trafficOutboxInitMarkerContent)
	info, err := os.Lstat(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to inspect traffic outbox initialization marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false, fmt.Errorf("traffic outbox initialization marker %q must be a private regular file (0600)", markerPath)
	}
	if err := validateTrafficOutboxLinkCount(info, markerPath); err != nil {
		return false, err
	}
	if info.Size() > int64(len(expected)) {
		return false, fmt.Errorf("traffic outbox initialization marker %q is invalid and must be reconciled manually", markerPath)
	}
	file, err := openTrafficOutboxFileNoFollow(markerPath)
	if err != nil {
		return false, fmt.Errorf("failed to securely open traffic outbox initialization marker: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return false, fmt.Errorf("traffic outbox initialization marker %q was replaced or became unsafe while opening: %v", markerPath, statErr)
	}
	if err := validateTrafficOutboxLinkCount(openedInfo, markerPath); err != nil {
		_ = file.Close()
		return false, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return false, fmt.Errorf("failed to read traffic outbox initialization marker: %v", errors.Join(readErr, closeErr))
	}
	if len(data) > len(expected) {
		return false, fmt.Errorf("traffic outbox initialization marker %q is invalid and must be reconciled manually", markerPath)
	}
	if string(data) != trafficOutboxInitMarkerContent {
		if len(data) < len(expected) && bytes.Equal(data, expected[:len(data)]) {
			return false, fmt.Errorf("%w %q", errTrafficOutboxPartialInitMarker, markerPath)
		}
		return false, fmt.Errorf("traffic outbox initialization marker %q is invalid and must be reconciled manually", markerPath)
	}
	return true, nil
}

func createTrafficOutboxInitMarker(path string) error {
	markerPath := path + ".init"
	if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("traffic outbox initialization marker %q already exists", markerPath)
		}
		return fmt.Errorf("failed to inspect traffic outbox initialization marker: %w", err)
	}
	if err := writeFileAtomic(markerPath, []byte(trafficOutboxInitMarkerContent), 0600); err != nil {
		return fmt.Errorf("failed to atomically create traffic outbox initialization marker: %w", err)
	}
	return nil
}

func repairPartialTrafficOutboxInitMarker(path string) error {
	if err := writeFileAtomic(path+".init", []byte(trafficOutboxInitMarkerContent), 0600); err != nil {
		return fmt.Errorf("failed to atomically repair traffic outbox initialization marker: %w", err)
	}
	return nil
}

func removeTrafficOutboxInitMarker(path string) error {
	if err := os.Remove(path + ".init"); err != nil {
		return fmt.Errorf("failed to remove completed traffic outbox initialization marker: %w", err)
	}
	return syncTrafficOutboxDirectory(filepath.Dir(path))
}

func syncTrafficOutboxDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open traffic outbox directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("failed to sync traffic outbox directory: %v", errors.Join(syncErr, closeErr))
	}
	return nil
}

// resolveTrafficOutboxPath resolves trusted system-level aliases such as
// macOS /var -> /private/var before any file is opened. A symlink used as the
// outbox directory itself is still rejected. All later checks and SQLite I/O
// use only the resolved path.
func resolveTrafficOutboxPath(path string) (string, error) {
	dir := filepath.Dir(path)
	current := dir
	var missing []string
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("traffic outbox directory %q must not be a symlink", current)
			}
			if !info.IsDir() {
				return "", fmt.Errorf("traffic outbox directory ancestor %q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("failed to inspect traffic outbox directory %q: %w", current, err)
		}
		missing = append(missing, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("failed to find an existing traffic outbox directory ancestor for %q", dir)
		}
		current = parent
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("failed to resolve traffic outbox directory ancestor %q: %w", current, err)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, missing[i])
	}
	if len(missing) == 0 {
		// Lstat above rejects a direct symlink, while EvalSymlinks safely
		// canonicalizes any platform-provided ancestor aliases.
		resolved, err = filepath.EvalSymlinks(dir)
		if err != nil {
			return "", fmt.Errorf("failed to resolve traffic outbox directory %q: %w", dir, err)
		}
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

func ensurePrivateTrafficOutboxDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create traffic outbox directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to inspect traffic outbox directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("traffic outbox directory %q must be a real directory", dir)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("traffic outbox directory %q must be private (0700); refusing to change permissions on an existing directory", dir)
	}
	return nil
}

func secureTrafficOutboxFiles(path string) error {
	candidates := []string{path}
	for _, suffix := range trafficOutboxSidecarSuffixes {
		candidates = append(candidates, path+suffix)
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to inspect SQLite traffic outbox file %q: %w", candidate, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite traffic outbox file %q must be a regular non-symlink file", candidate)
		}
		if info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("SQLite traffic outbox file %q must be private (0600); refusing to change existing file permissions", candidate)
		}
		if err := validateTrafficOutboxLinkCount(info, candidate); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateTrafficOutboxFiles(path string, expectedDir, expectedMain os.FileInfo) error {
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("traffic outbox directory is missing, replaced, or not private: %v", err)
	}
	if expectedDir != nil && !os.SameFile(expectedDir, dirInfo) {
		return errors.New("traffic outbox directory was replaced")
	}
	mainInfo, err := os.Lstat(path)
	if err != nil || mainInfo.Mode()&os.ModeSymlink != 0 || !mainInfo.Mode().IsRegular() || mainInfo.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("traffic outbox file is missing, replaced, or not private: %v", err)
	}
	if expectedMain != nil && !os.SameFile(expectedMain, mainInfo) {
		return errors.New("traffic outbox file was replaced")
	}
	if err := validateTrafficOutboxLinkCount(mainInfo, path); err != nil {
		return err
	}
	for _, suffix := range trafficOutboxSidecarSuffixes {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("SQLite traffic outbox sidecar %q is unsafe: %v", path+suffix, err)
		}
		if err := validateTrafficOutboxLinkCount(info, path+suffix); err != nil {
			return err
		}
	}
	return nil
}

func trafficOutboxFilesSize(path string) (int64, error) {
	var total int64
	candidates := []string{path}
	for _, suffix := range trafficOutboxSidecarSuffixes {
		candidates = append(candidates, path+suffix)
	}
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("outbox file %q is not regular", candidate)
		}
		total += info.Size()
	}
	return total, nil
}

func newTrafficBatchID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("failed to generate traffic batch ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

func mergeTrafficDeltas(groups ...[]TrafficDelta) []TrafficDelta {
	merged := make(map[int]TrafficDelta)
	for _, group := range groups {
		for _, delta := range group {
			current := merged[delta.UserID]
			current.UserID = delta.UserID
			current.Upload += delta.Upload
			current.Download += delta.Download
			merged[delta.UserID] = current
		}
	}
	out := make([]TrafficDelta, 0, len(merged))
	for _, delta := range merged {
		out = append(out, delta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".sshappy-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(perm); err != nil {
		return err
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return err
	}
	directory, openErr := os.Open(dir)
	if openErr != nil {
		return openErr
	}
	defer directory.Close()
	return directory.Sync()
}

func removeFileAtomic(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
