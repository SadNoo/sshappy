package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeTrafficDatabase struct {
	err      error
	errs     []error
	batchIDs []string
	nodes    []Node
	deltas   [][]TrafficDelta
	onReport func()
}

type blockingContextTrafficDatabase struct {
	contextCalls int
}

func (d *blockingContextTrafficDatabase) ReportTraffic(Node, string, []TrafficDelta) error {
	return errors.New("non-context traffic database API was used")
}

func (d *blockingContextTrafficDatabase) ReportTrafficContext(ctx context.Context, _ Node, _ string, _ []TrafficDelta) error {
	d.contextCalls++
	<-ctx.Done()
	return ctx.Err()
}

func (d *fakeTrafficDatabase) ReportTraffic(node Node, batchID string, traffic []TrafficDelta) error {
	if d.onReport != nil {
		d.onReport()
	}
	if len(d.errs) > 0 {
		err := d.errs[0]
		d.errs = d.errs[1:]
		if err != nil {
			return err
		}
	}
	if d.err != nil {
		return d.err
	}
	d.batchIDs = append(d.batchIDs, batchID)
	d.nodes = append(d.nodes, node)
	d.deltas = append(d.deltas, append([]TrafficDelta(nil), traffic...))
	return nil
}

func newTestTrafficReporter(t *testing.T, path string) *trafficReporter {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reporter.Close() })
	return reporter
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testBillingNode() Node {
	return Node{ID: 116, TrafficRate: 1.5}
}

func TestTrafficBatchCanonicalSHA256KnownVector(t *testing.T) {
	batch := TrafficBatch{
		ID:              "0123456789abcdef0123456789abcdef",
		CreatedAt:       1234567890,
		NodeID:          116,
		TrafficRateText: "1.5",
		Deltas: []TrafficDelta{
			{UserID: 7, Upload: 10, Download: 20},
			{UserID: 9, Upload: 30, Download: 40},
		},
	}
	sum := trafficBatchSHA256(batch)
	got := hex.EncodeToString(sum[:])
	const want = "7d4e291a1d809a4b7af63315e37ab430e6ac12ebf7554a092640ab5a1cad482d"
	if got != want {
		t.Fatalf("canonical SHA-256 = %s, want %s", got, want)
	}
	unreplayable := batch
	unreplayable.TrafficRateText = "1e+308"
	unreplayable.Deltas = []TrafficDelta{{UserID: 7, Upload: 1}}
	unreplayable.PayloadSHA256 = trafficBatchSHA256(unreplayable)
	if err := validateAndVerifyTrafficBatch(unreplayable); err == nil || !strings.Contains(err.Error(), "cannot be replayed safely") {
		t.Fatalf("validly hashed but unreplayable batch validation error=%v", err)
	}
}

func TestValidateAndCountTrafficBatchesRejectsNonpositiveSequence(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=private")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE traffic_batches (sequence INTEGER PRIMARY KEY); INSERT INTO traffic_batches(sequence) VALUES (0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := validateAndCountTrafficBatches(t.Context(), db); err == nil || !strings.Contains(err.Error(), "non-positive") {
		t.Fatalf("non-positive sequence validation error=%v", err)
	}
}

func TestCanonicalTrafficDeltasAreStableAndChecked(t *testing.T) {
	first, err := canonicalTrafficDeltas([]TrafficDelta{
		{UserID: 9, Download: 3},
		{UserID: 7, Upload: 10},
		{UserID: 7, Download: 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalTrafficDeltas([]TrafficDelta{
		{UserID: 7, Upload: 10, Download: 20},
		{UserID: 9, Download: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].UserID != 7 || first[1].UserID != 9 || !equalTrafficDeltas(first, second) {
		t.Fatalf("canonical deltas differ: first=%+v second=%+v", first, second)
	}
	base := TrafficBatch{ID: "0123456789abcdef0123456789abcdef", CreatedAt: 123, NodeID: 116, TrafficRateText: "1.5", Deltas: first}
	if trafficBatchSHA256(base) != trafficBatchSHA256(TrafficBatch{ID: base.ID, CreatedAt: base.CreatedAt, NodeID: base.NodeID, TrafficRateText: base.TrafficRateText, Deltas: second}) {
		t.Fatal("equivalent canonical deltas produced different hashes")
	}
	mutations := []TrafficBatch{
		{ID: "1123456789abcdef0123456789abcdef", CreatedAt: base.CreatedAt, NodeID: base.NodeID, TrafficRateText: base.TrafficRateText, Deltas: base.Deltas},
		{ID: base.ID, CreatedAt: base.CreatedAt + 1, NodeID: base.NodeID, TrafficRateText: base.TrafficRateText, Deltas: base.Deltas},
		{ID: base.ID, CreatedAt: base.CreatedAt, NodeID: base.NodeID + 1, TrafficRateText: base.TrafficRateText, Deltas: base.Deltas},
		{ID: base.ID, CreatedAt: base.CreatedAt, NodeID: base.NodeID, TrafficRateText: "2", Deltas: base.Deltas},
		{ID: base.ID, CreatedAt: base.CreatedAt, NodeID: base.NodeID, TrafficRateText: base.TrafficRateText, Deltas: []TrafficDelta{{UserID: 7, Upload: 11, Download: 20}, {UserID: 9, Download: 3}}},
	}
	for i, mutation := range mutations {
		if trafficBatchSHA256(base) == trafficBatchSHA256(mutation) {
			t.Fatalf("mutation %d did not change canonical hash", i)
		}
	}
	if _, err := canonicalTrafficDeltas([]TrafficDelta{{UserID: 7, Upload: math.MaxInt64}, {UserID: 7, Upload: 1}}); err == nil {
		t.Fatal("traffic overflow was accepted")
	}
}

func TestTrafficReporterRejectsUnreplayableBillingBeforePersistence(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "state", "traffic.sqlite3"))
	err := reporter.Capture(Node{ID: 116, TrafficRate: 1e308}, []TrafficDelta{{UserID: 7, Upload: 1}})
	if !errors.Is(err, errTrafficOutboxPersistence) || !strings.Contains(err.Error(), "replayed safely") {
		t.Fatalf("unreplayable billing error=%v", err)
	}
	if reporter.PendingBatches() != 0 {
		t.Fatalf("unreplayable batch increased pending count to %d", reporter.PendingBatches())
	}
	var rows int
	if queryErr := reporter.db.QueryRow("SELECT COUNT(*) FROM traffic_batches").Scan(&rows); queryErr != nil || rows != 0 {
		t.Fatalf("unreplayable batch reached durable storage: rows=%d err=%v", rows, queryErr)
	}
}

func TestTrafficReporterPersistsMultipleBatchesAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "traffic-outbox.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if _, err := os.Lstat(path + ".init"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed initialization left marker behind: %v", err)
	}
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 10, Download: 20}}); err != nil {
		t.Fatal(err)
	}
	firstID := readAllTrafficBatchesForTest(t, reporter)[0].ID
	if len(firstID) != 32 {
		t.Fatalf("batch ID length = %d, want 32", len(firstID))
	}
	secondNode := Node{ID: 117, TrafficRate: 2.25}
	if err := reporter.Capture(secondNode, []TrafficDelta{{UserID: 7, Upload: 5}, {UserID: 9, Download: 3}}); err != nil {
		t.Fatal(err)
	}
	if metrics := reporter.Metrics(time.Now()); metrics.Batches != 2 || metrics.Users != 2 || metrics.Records != 3 || metrics.UploadBytes != 15 || metrics.DownloadBytes != 23 || metrics.FileBytes == 0 {
		t.Fatalf("unexpected outbox metrics: %+v", metrics)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded := newTestTrafficReporter(t, path)
	reloadedBatches := readAllTrafficBatchesForTest(t, reloaded)
	if len(reloadedBatches) != 2 || reloadedBatches[0].ID != firstID {
		t.Fatalf("reloaded batches = %+v", reloadedBatches)
	}
	database := &fakeTrafficDatabase{}
	if err := reloaded.Flush(database); err != nil {
		t.Fatal(err)
	}
	if len(database.batchIDs) != 2 || database.nodes[0].ID != 116 || database.nodes[0].TrafficRate != 1.5 || database.nodes[1].ID != 117 || database.nodes[1].TrafficRate != 2.25 {
		t.Fatalf("flush did not use frozen billing contexts: IDs=%v nodes=%+v", database.batchIDs, database.nodes)
	}
	if reloaded.PendingBatches() != 0 {
		t.Fatalf("pending batches = %d, want zero", reloaded.PendingBatches())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("SQLite outbox should remain after queue drain: %v", err)
	}
}

func TestTrafficReporterSerializesConcurrentCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	const captures = 32
	start := make(chan struct{})
	errs := make(chan error, captures)
	var wg sync.WaitGroup
	for i := range captures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: i + 1, Upload: 1}})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if reporter.PendingBatches() != captures {
		t.Fatalf("pending batches=%d, want %d", reporter.PendingBatches(), captures)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded := newTestTrafficReporter(t, path)
	if reloaded.PendingBatches() != captures {
		t.Fatalf("reloaded pending batches=%d, want %d", reloaded.PendingBatches(), captures)
	}
}

func TestTrafficReporterProcessLockRejectsSecondWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "traffic.sqlite3")
	first := newTestTrafficReporter(t, path)
	second, err := newTrafficReporter(path)
	if err == nil || second != nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second writer startup = reporter=%v err=%v", second, err)
	}
	assertMode(t, path+".lock", 0600)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newTestTrafficReporter(t, path)
	if reopened.PendingBatches() != 0 {
		t.Fatalf("reopened outbox has %d pending batches", reopened.PendingBatches())
	}
}

func TestTrafficReporterDirectoryLockSurvivesVisibleLockReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "traffic.sqlite3")
	first := newTestTrafficReporter(t, path)
	movedLock := path + ".lock.moved"
	if err := os.Rename(path+".lock", movedLock); err != nil {
		t.Fatal(err)
	}
	second, err := newTrafficReporter(path)
	if err == nil || second != nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second writer bypassed state-directory lock: reporter=%v err=%v", second, err)
	}
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected second writer recreated visible lock: %v", err)
	}
	if err := first.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 1}}); !errors.Is(err, errTrafficOutboxPersistence) || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("first writer did not fail closed after visible lock replacement: %v", err)
	}
	if err := first.Close(); !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("poisoned first writer close error=%v", err)
	}
}

func TestTrafficReporterRejectsUnsafeVisibleProcessLocks(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		target := filepath.Join(privateTestDir(t), "lock-target")
		if err := os.WriteFile(target, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+".lock"); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("symlink process lock was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		target := filepath.Join(privateTestDir(t), "lock-target")
		if err := os.WriteFile(target, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, path+".lock"); err != nil {
			t.Skipf("hard links are unavailable on this filesystem: %v", err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("hardlink process lock was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("permissive mode", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path+".lock", nil, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+".lock", 0644); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("permissive process lock was accepted: reporter=%v err=%v", reporter, err)
		}
		info, err := os.Stat(path + ".lock")
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("permissive process lock mode was changed: info=%v err=%v", info, err)
		}
	})
}

func TestTrafficReporterRejectsHardLinkedMainFile(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source", "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, sourcePath)
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(t.TempDir(), "alias")
	if err := os.Mkdir(aliasDir, 0700); err != nil {
		t.Fatal(err)
	}
	aliasPath := filepath.Join(aliasDir, "traffic.sqlite3")
	if err := os.Link(sourcePath, aliasPath); err != nil {
		t.Skipf("hard links are unavailable on this filesystem: %v", err)
	}
	alias, err := newTrafficReporter(aliasPath)
	if err == nil || alias != nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Fatalf("hard-linked outbox startup = reporter=%v err=%v", alias, err)
	}
}

func TestTrafficReporterFlushContextIsBoundedAndCancelable(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "state", "traffic.sqlite3"))
	for userID := 1; userID <= 3; userID++ {
		if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: userID, Upload: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	database := &fakeTrafficDatabase{}
	flushed, err := reporter.FlushContext(t.Context(), database, 2)
	if err != nil || flushed != 2 || reporter.PendingBatches() != 1 || len(database.batchIDs) != 2 {
		t.Fatalf("bounded flush = flushed=%d pending=%d IDs=%v err=%v", flushed, reporter.PendingBatches(), database.batchIDs, err)
	}
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	flushed, err = reporter.FlushContext(canceledCtx, database, 0)
	if !errors.Is(err, context.Canceled) || flushed != 0 || reporter.PendingBatches() != 1 || len(database.batchIDs) != 2 {
		t.Fatalf("canceled flush = flushed=%d pending=%d IDs=%v err=%v", flushed, reporter.PendingBatches(), database.batchIDs, err)
	}
	flushed, err = reporter.FlushContext(t.Context(), database, 0)
	if err != nil || flushed != 1 || reporter.PendingBatches() != 0 || len(database.batchIDs) != 3 {
		t.Fatalf("final flush = flushed=%d pending=%d IDs=%v err=%v", flushed, reporter.PendingBatches(), database.batchIDs, err)
	}
}

func TestTrafficReporterFlushContextCancelsBlockedDatabase(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "state", "traffic.sqlite3"))
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 1}}); err != nil {
		t.Fatal(err)
	}
	database := &blockingContextTrafficDatabase{}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	flushed, err := reporter.FlushContext(ctx, database, 0)
	if !errors.Is(err, context.DeadlineExceeded) || flushed != 0 || reporter.PendingBatches() != 1 || database.contextCalls != 1 {
		t.Fatalf("blocked flush = flushed=%d pending=%d contextCalls=%d err=%v", flushed, reporter.PendingBatches(), database.contextCalls, err)
	}
}

func TestReportTrafficContextBoundsBacklogDrain(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "state", "traffic.sqlite3"))
	for userID := 1; userID <= trafficOutboxFlushBatchLimit+6; userID++ {
		if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: userID, Upload: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	state := NewState()
	state.AddTraffic(999, 10, 20)
	database := &fakeTrafficDatabase{}
	flushed, err := reportTrafficContext(t.Context(), database, testBillingNode(), state, reporter, &databaseHealth{})
	if err != nil || !flushed || len(database.batchIDs) != trafficOutboxFlushBatchLimit {
		t.Fatalf("bounded report = flushed=%v IDs=%d err=%v", flushed, len(database.batchIDs), err)
	}
	if want := 7; reporter.PendingBatches() != want {
		t.Fatalf("pending batches=%d, want %d (six backlog plus newly captured batch)", reporter.PendingBatches(), want)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("new traffic remained only in memory: %+v", metrics)
	}
}

func TestReportFinalTrafficCapturesBeforeCanceledFlush(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "state", "traffic.sqlite3"))
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 5}}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(8, 10, 20)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	database := &fakeTrafficDatabase{}
	if err := reportFinalTrafficContext(ctx, database, testBillingNode(), state, reporter, &databaseHealth{}, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if len(database.batchIDs) != 0 {
		t.Fatalf("canceled final flush reached remote database: %v", database.batchIDs)
	}
	metrics := reporter.Metrics(time.Now())
	if metrics.Batches != 2 || metrics.UploadBytes != 15 || metrics.DownloadBytes != 20 {
		t.Fatalf("newest final traffic was not durable before flush: %+v", metrics)
	}
	if pending := state.PendingMetrics(); pending.TrafficUsers != 0 {
		t.Fatalf("final traffic remained only in memory: %+v", pending)
	}
}

func TestTrafficReporterSQLiteConfigurationAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 1}}); err != nil {
		t.Fatal(err)
	}
	var journal string
	if err := reporter.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal_mode=%q err=%v", journal, err)
	}
	for name, want := range map[string]int{"synchronous": 2, "foreign_keys": 1, "busy_timeout": trafficOutboxBusyTimeoutMS, "user_version": trafficOutboxSchemaVersion, "application_id": trafficOutboxApplicationID} {
		var got int
		if err := reporter.db.QueryRow("PRAGMA " + name).Scan(&got); err != nil || got != want {
			t.Fatalf("PRAGMA %s=%d err=%v, want %d", name, got, err, want)
		}
	}
	if reporter.db.Stats().MaxOpenConnections != 1 {
		t.Fatalf("MaxOpenConnections=%d, want single writer", reporter.db.Stats().MaxOpenConnections)
	}
	var rateType, storedRate string
	if err := reporter.db.QueryRow("SELECT typeof(traffic_rate), traffic_rate FROM traffic_batches").Scan(&rateType, &storedRate); err != nil || rateType != "text" || storedRate != "1.5" {
		t.Fatalf("stored traffic rate=(type=%q value=%q err=%v), want canonical text", rateType, storedRate, err)
	}
	assertMode(t, dir, 0700)
	assertMode(t, path, 0600)
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("WAL sidecar is missing while reporter is open: %v", err)
	}
	assertMode(t, path+"-wal", 0600)
	if _, err := os.Stat(path + "-shm"); err == nil {
		assertMode(t, path+"-shm", 0600)
	}
}

func TestTrafficReporterPreservesLegacyJSONAndRefusesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"id":"0123456789abcdef0123456789abcdef","deltas":[{"UserID":7,"Upload":10,"Download":20}]}`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	reporter, err := newTrafficReporter(path)
	if err == nil || reporter != nil || !strings.Contains(err.Error(), "not SQLite") || !strings.Contains(err.Error(), "preserved") {
		t.Fatalf("legacy JSON startup = reporter=%v err=%v", reporter, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy JSON was changed: data=%q err=%v", got, readErr)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, statErr := os.Lstat(path + suffix); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("legacy JSON gained SQLite sidecar %q: %v", suffix, statErr)
		}
	}
}

func TestTrafficReporterRejectsUnsafePaths(t *testing.T) {
	t.Run("file symlink", func(t *testing.T) {
		dir := privateTestDir(t)
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "outbox.sqlite3")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("file symlink was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("directory symlink", func(t *testing.T) {
		root := privateTestDir(t)
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(filepath.Join(linkDir, "outbox.sqlite3")); err == nil || reporter != nil {
			t.Fatalf("directory symlink was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("non regular file", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "outbox.sqlite3")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("directory at file path was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run("orphaned sidecar "+suffix, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "outbox.sqlite3")
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path+suffix); err != nil {
				t.Fatal(err)
			}
			if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
				t.Fatalf("orphaned %s sidecar was accepted: reporter=%v err=%v", suffix, reporter, err)
			}
		})
	}
}

func TestTrafficReporterRecoversSafeInterruptedInitialization(t *testing.T) {
	t.Run("unmarked zero-byte main file is preserved", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		reporter, err := newTrafficReporter(path)
		if err == nil || reporter != nil {
			t.Fatalf("unmarked empty file was accepted: reporter=%v err=%v", reporter, err)
		}
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() != 0 {
			t.Fatalf("unmarked empty file was changed: info=%v err=%v", info, statErr)
		}
	})

	t.Run("marked zero-byte main file", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := createTrafficOutboxInitMarker(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		reporter := newTestTrafficReporter(t, path)
		if reporter.PendingBatches() != 0 {
			t.Fatalf("recovered empty outbox has %d batches", reporter.PendingBatches())
		}
		if _, err := os.Lstat(path + ".init"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery left initialization marker behind: %v", err)
		}
	})

	t.Run("marked uninitialized SQLite header", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := createTrafficOutboxInitMarker(path); err != nil {
			t.Fatal(err)
		}
		raw, err := sql.Open("sqlite", trafficOutboxDSN(path))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec("PRAGMA journal_mode=WAL"); err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		reporter := newTestTrafficReporter(t, path)
		if reporter.PendingBatches() != 0 {
			t.Fatalf("recovered uninitialized outbox has %d batches", reporter.PendingBatches())
		}
	})

	t.Run("partial marker before main file", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path+".init", []byte(trafficOutboxInitMarkerContent[:12]), 0600); err != nil {
			t.Fatal(err)
		}
		reporter := newTestTrafficReporter(t, path)
		if reporter.PendingBatches() != 0 {
			t.Fatalf("recovered partial initialization has %d batches", reporter.PendingBatches())
		}
		if _, err := os.Lstat(path + ".init"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial marker recovery left marker behind: %v", err)
		}
	})

	t.Run("partial marker with zero-byte main file", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path+".init", []byte(trafficOutboxInitMarkerContent[:12]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		reporter := newTestTrafficReporter(t, path)
		if reporter.PendingBatches() != 0 {
			t.Fatalf("recovered partial initialization has %d batches", reporter.PendingBatches())
		}
		if _, err := os.Lstat(path + ".init"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial marker recovery left marker behind: %v", err)
		}
	})
}

func TestTrafficReporterRejectsUnsafeInitializationMarkers(t *testing.T) {
	validContent := []byte(trafficOutboxInitMarkerContent)

	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		target := filepath.Join(privateTestDir(t), "marker-target")
		if err := os.WriteFile(target, validContent, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+".init"); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("symlink marker was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		target := filepath.Join(privateTestDir(t), "marker-target")
		if err := os.WriteFile(target, validContent, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, path+".init"); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("hardlink marker was accepted: reporter=%v err=%v", reporter, err)
		}
	})

	t.Run("permissive mode", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path+".init", validContent, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+".init", 0644); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("permissive marker was accepted: reporter=%v err=%v", reporter, err)
		}
		info, err := os.Stat(path + ".init")
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("permissive marker mode was changed: info=%v err=%v", info, err)
		}
	})

	t.Run("invalid content", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		const content = "not-an-sshappy-marker\n"
		if err := os.WriteFile(path+".init", []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("invalid marker was accepted: reporter=%v err=%v", reporter, err)
		}
		data, err := os.ReadFile(path + ".init")
		if err != nil || string(data) != content {
			t.Fatalf("invalid marker was changed: data=%q err=%v", data, err)
		}
	})

	t.Run("oversized sparse marker", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
		if err := os.WriteFile(path+".init", nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path+".init", 1<<40); err != nil {
			t.Skipf("sparse files are unavailable on this filesystem: %v", err)
		}
		if reporter, err := newTrafficReporter(path); err == nil || reporter != nil {
			t.Fatalf("oversized marker was accepted: reporter=%v err=%v", reporter, err)
		}
		info, err := os.Stat(path + ".init")
		if err != nil || info.Size() != 1<<40 {
			t.Fatalf("oversized marker was changed: info=%v err=%v", info, err)
		}
	})
}

func TestNewTrafficReporterContextReturnsBeforeCreatingStateWhenCanceled(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "traffic.sqlite3")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reporter, err := newTrafficReporterContext(ctx, path)
	if !errors.Is(err, context.Canceled) || reporter != nil {
		t.Fatalf("canceled startup = reporter=%v err=%v", reporter, err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled startup created outbox state: %v", statErr)
	}
}

func TestTrafficReporterQueuesWhileRemoteDatabaseIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	databaseErr := errors.New("database unavailable")
	database := &fakeTrafficDatabase{err: databaseErr}
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Flush(database); !errors.Is(err, databaseErr) {
		t.Fatalf("flush error=%v, want %v", err, databaseErr)
	}
	if err := reporter.Capture(Node{ID: 117, TrafficRate: 2}, []TrafficDelta{{UserID: 7, Download: 20}}); err != nil {
		t.Fatal(err)
	}
	queued := readAllTrafficBatchesForTest(t, reporter)
	wantIDs := []string{queued[0].ID, queued[1].ID}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded := newTestTrafficReporter(t, path)
	if reloaded.PendingBatches() != 2 {
		t.Fatalf("pending batches=%d, want 2", reloaded.PendingBatches())
	}
	database.err = nil
	if err := reloaded.Flush(database); err != nil {
		t.Fatal(err)
	}
	if len(database.batchIDs) != 2 || database.batchIDs[0] != wantIDs[0] || database.batchIDs[1] != wantIDs[1] {
		t.Fatalf("reported IDs=%v, want %v", database.batchIDs, wantIDs)
	}
}

func TestTrafficReporterDetectsPayloadCorruptionBeforeFlush(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "traffic.sqlite3"))
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.db.Exec("UPDATE traffic_deltas SET upload = upload + 1"); err != nil {
		t.Fatal(err)
	}
	database := &fakeTrafficDatabase{}
	firstErr := reporter.Flush(database)
	if !errors.Is(firstErr, errTrafficOutboxPersistence) || !strings.Contains(firstErr.Error(), "SHA-256 mismatch") {
		t.Fatalf("corrupt flush error=%v", firstErr)
	}
	if len(database.batchIDs) != 0 {
		t.Fatalf("corrupt payload reached remote database: %v", database.batchIDs)
	}
	secondErr := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 8, Upload: 1}})
	if secondErr != firstErr {
		t.Fatalf("poisoned reporter returned different error: first=%v second=%v", firstErr, secondErr)
	}
	if err := reporter.Flush(database); err != firstErr || len(database.batchIDs) != 0 {
		t.Fatalf("poisoned reporter retried work: err=%v IDs=%v", err, database.batchIDs)
	}
}

func TestTrafficReporterRejectsHashCorruptionOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.db.Exec("UPDATE traffic_batches SET payload_sha256 = zeroblob(32)"); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newTrafficReporter(path)
	if err == nil || reloaded != nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("hash-corrupt restart=reporter=%v err=%v", reloaded, err)
	}
}

func TestTrafficReporterRejectsUnsupportedSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if _, err := reporter.db.Exec("PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newTrafficReporter(path)
	if err == nil || reloaded != nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported schema restart=reporter=%v err=%v", reloaded, err)
	}
}

func TestTrafficReporterRejectsStructurallyWrongSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if _, err := reporter.db.Exec("DROP TABLE traffic_deltas"); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.db.Exec(`CREATE TABLE traffic_deltas (
        batch_sequence INTEGER NOT NULL,
        ordinal INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        upload INTEGER NOT NULL,
        download INTEGER NOT NULL
    ) STRICT`); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newTrafficReporter(path)
	if err == nil || reloaded != nil || !strings.Contains(err.Error(), "definition does not match") {
		t.Fatalf("structurally wrong schema restart=reporter=%v err=%v", reloaded, err)
	}
}

func TestTrafficReporterPostCommitLocalFailurePoisonsReporter(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "traffic.sqlite3"))
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	database := &fakeTrafficDatabase{}
	database.onReport = func() {
		database.onReport = nil
		_ = reporter.db.Close()
	}
	firstErr := reporter.Flush(database)
	if !errors.Is(firstErr, errTrafficOutboxPersistence) || !strings.Contains(firstErr.Error(), "after database commit") {
		t.Fatalf("post-commit local error=%v", firstErr)
	}
	if len(database.batchIDs) != 1 {
		t.Fatalf("remote database did not commit first: %v", database.batchIDs)
	}
	if reporter.PendingBatches() != 1 {
		t.Fatalf("failed local ack removed durable batch; pending=%d", reporter.PendingBatches())
	}
	if err := reporter.Flush(database); err != firstErr || len(database.batchIDs) != 1 {
		t.Fatalf("poisoned reporter retried remote commit: err=%v IDs=%v", err, database.batchIDs)
	}
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 8, Upload: 1}}); err != firstErr {
		t.Fatalf("poisoned reporter allowed capture: %v", err)
	}
	wantID := database.batchIDs[0]
	_ = reporter.Close()
	reloaded := newTestTrafficReporter(t, reporter.path)
	retryDatabase := &fakeTrafficDatabase{}
	if err := reloaded.Flush(retryDatabase); err != nil {
		t.Fatal(err)
	}
	if len(retryDatabase.batchIDs) != 1 || retryDatabase.batchIDs[0] != wantID {
		t.Fatalf("retry did not preserve idempotent batch ID: got %v want %s", retryDatabase.batchIDs, wantID)
	}
}

func TestReportTrafficPersistsNewBatchAfterBacklogFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 100}}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(7, 0, 200)
	databaseErr := errors.New("database unavailable")
	database := &fakeTrafficDatabase{err: databaseErr}
	if _, err := reportTraffic(database, Node{ID: 117, TrafficRate: 2}, state, reporter, &databaseHealth{}); !errors.Is(err, databaseErr) {
		t.Fatalf("report error=%v, want %v", err, databaseErr)
	}
	batches := readAllTrafficBatchesForTest(t, reporter)
	if len(batches) != 2 || batches[0].NodeID != 116 || batches[1].NodeID != 117 || batches[1].TrafficRateText != "2" {
		t.Fatalf("new traffic was not durably separated with frozen context: %+v", batches)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("captured traffic remained only in memory: %+v", metrics)
	}
}

func TestReportTrafficCaptureFailureRestoresMemory(t *testing.T) {
	state := NewState()
	state.AddTraffic(7, 100, 200)
	reporter := &trafficReporter{path: filepath.Join(t.TempDir(), "missing.sqlite3")}
	_, err := reportTraffic(&fakeTrafficDatabase{}, testBillingNode(), state, reporter, &databaseHealth{})
	if !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("capture error=%v, want fatal persistence error", err)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 1 || metrics.TrafficUploadBytes != 100 || metrics.TrafficDownloadBytes != 200 {
		t.Fatalf("capture failure lost in-memory traffic: %+v", metrics)
	}
}

func TestFinalTrafficPersistsWhenRemoteDatabaseIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 50}}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(7, 100, 200)
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	health := &databaseHealth{}
	if err := reportFinalTraffic(database, testBillingNode(), state, reporter, health, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if metrics := reporter.Metrics(time.Now()); metrics.Batches != 2 || metrics.UploadBytes != 150 || metrics.DownloadBytes != 200 {
		t.Fatalf("final traffic was not persisted: %+v", metrics)
	}
	if health.Snapshot().Failures != 1 {
		t.Fatalf("database failure was not recorded: %+v", health.Snapshot())
	}
}

func TestTrafficReporterRejectsPermissiveExistingFileWithoutChangingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "traffic.sqlite3")
	reporter := newTestTrafficReporter(t, path)
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	reopened, err := newTrafficReporter(path)
	if err == nil || reopened != nil || !strings.Contains(err.Error(), "must be private") {
		t.Fatalf("permissive file startup = reporter=%v err=%v", reopened, err)
	}
	assertMode(t, dir, 0700)
	assertMode(t, path, 0644)
}

func TestTrafficReporterRejectsPermissiveExistingDirectoryWithoutChangingIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "traffic.sqlite3")
	reporter, err := newTrafficReporter(path)
	if err == nil || reporter != nil || !strings.Contains(err.Error(), "must be private") {
		t.Fatalf("permissive directory startup = reporter=%v err=%v", reporter, err)
	}
	assertMode(t, dir, 0755)
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outbox was created in rejected directory: %v", statErr)
	}
}

func TestTrafficReporterCloseIsIdempotentAndFinal(t *testing.T) {
	reporter := newTestTrafficReporter(t, filepath.Join(t.TempDir(), "traffic.sqlite3"))
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if err := reporter.Capture(testBillingNode(), []TrafficDelta{{UserID: 7, Upload: 1}}); !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("Capture after Close error=%v", err)
	}
	if err := reporter.Flush(&fakeTrafficDatabase{}); !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("Flush after Close error=%v", err)
	}
}

func equalTrafficDeltas(a, b []TrafficDelta) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readAllTrafficBatchesForTest(t *testing.T, reporter *trafficReporter) []TrafficBatch {
	t.Helper()
	batches, err := loadTrafficBatches(t.Context(), reporter.db, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return batches
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%v, want %v", path, got, want)
	}
}
