package panel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDatabaseContextAPIsReturnCanceledContextBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	database := &Database{}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "open database",
			call: func() error {
				_, err := OpenDatabaseContext(ctx, Config{})
				return err
			},
		},
		{
			name: "validate schema",
			call: func() error {
				return validateDatabaseSchemaContext(ctx, nil, "test")
			},
		},
		{
			name: "load node",
			call: func() error {
				_, err := database.LoadNodeContext(ctx)
				return err
			},
		},
		{
			name: "load users",
			call: func() error {
				_, err := database.LoadUsersContext(ctx, Node{})
				return err
			},
		},
		{
			name: "report traffic",
			call: func() error {
				return database.ReportTrafficContext(ctx, Node{}, "batch", []TrafficDelta{{UserID: 1}})
			},
		},
		{
			name: "cleanup traffic batches",
			call: func() error {
				_, err := database.CleanupTrafficBatchesContext(ctx, 1, 1)
				return err
			},
		},
		{
			name: "report alive IPs",
			call: func() error {
				return database.ReportAliveIPsContext(ctx, Node{}, map[int]map[string]struct{}{1: {"192.0.2.1": {}}})
			},
		},
		{
			name: "report node status",
			call: func() error {
				return database.ReportNodeStatusContext(ctx, Node{}, 0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context cancellation, got %v", err)
			}
		})
	}
}

func TestDatabaseContextAPIsHonorDeadlineDuringSQL(t *testing.T) {
	database := newBlockingContextDatabase(t)

	tests := []struct {
		name string
		call func(context.Context) error
	}{
		{
			name: "schema query",
			call: func(ctx context.Context) error {
				return validateDatabaseSchemaContext(ctx, database.db, "test")
			},
		},
		{
			name: "load node query",
			call: func(ctx context.Context) error {
				_, err := database.LoadNodeContext(ctx)
				return err
			},
		},
		{
			name: "load users query",
			call: func(ctx context.Context) error {
				_, err := database.LoadUsersContext(ctx, Node{})
				return err
			},
		},
		{
			name: "traffic advisory lock",
			call: func(ctx context.Context) error {
				return database.ReportTrafficContext(ctx, Node{ID: 1, TrafficRate: 1}, "batch", []TrafficDelta{{UserID: 1, Upload: 1}})
			},
		},
		{
			name: "cleanup exec",
			call: func(ctx context.Context) error {
				_, err := database.CleanupTrafficBatchesContext(ctx, 1, 1)
				return err
			},
		},
		{
			name: "alive IP transaction",
			call: func(ctx context.Context) error {
				return database.ReportAliveIPsContext(ctx, Node{}, map[int]map[string]struct{}{1: {"192.0.2.1": {}}})
			},
		},
		{
			name: "node status transaction",
			call: func(ctx context.Context) error {
				return database.ReportNodeStatusContext(ctx, Node{}, 0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
			defer cancel()
			if err := test.call(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline exceeded, got %v", err)
			}
		})
	}
}

const blockingContextDriverName = "sshappy-blocking-context-test"

var registerBlockingContextDriver sync.Once

func newBlockingContextDatabase(t *testing.T) *Database {
	t.Helper()
	registerBlockingContextDriver.Do(func() {
		sql.Register(blockingContextDriverName, blockingContextDriver{})
	})
	db, err := sql.Open(blockingContextDriverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close blocking database: %v", err)
		}
	})
	return &Database{
		db: db,
		config: Config{
			MySQLIOTimeoutSeconds: 1,
		},
	}
}

var errDatabaseContextMissing = errors.New("database operation did not receive a cancellable context")

type blockingContextDriver struct{}

func (blockingContextDriver) Open(string) (driver.Conn, error) {
	return blockingContextConn{}, nil
}

type blockingContextConn struct{}

func (blockingContextConn) Prepare(string) (driver.Stmt, error) {
	return nil, errDatabaseContextMissing
}

func (blockingContextConn) Close() error {
	return nil
}

func (blockingContextConn) Begin() (driver.Tx, error) {
	return nil, errDatabaseContextMissing
}

func (blockingContextConn) Ping(ctx context.Context) error {
	return waitForDatabaseContext(ctx)
}

func (blockingContextConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	return nil, waitForDatabaseContext(ctx)
}

func (blockingContextConn) ExecContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	return nil, waitForDatabaseContext(ctx)
}

func (blockingContextConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	return nil, waitForDatabaseContext(ctx)
}

func waitForDatabaseContext(ctx context.Context) error {
	if ctx.Done() == nil {
		return errDatabaseContextMissing
	}
	<-ctx.Done()
	return ctx.Err()
}
