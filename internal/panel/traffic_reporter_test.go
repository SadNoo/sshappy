package panel

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeTrafficDatabase struct {
	err      error
	errs     []error
	batchIDs []string
	nodes    []Node
	onReport func()
}

func TestOnlyOutboxPersistenceFailureStopsAccounting(t *testing.T) {
	if fatalTrafficReportError(errors.New("database unavailable")) {
		t.Fatal("ordinary database failure would stop the relay")
	}
	if !fatalTrafficReportError(fmt.Errorf("capture failed: %w", errTrafficOutboxPersistence)) {
		t.Fatal("outbox persistence failure would not stop the relay")
	}
}

func (d *fakeTrafficDatabase) ReportTraffic(node Node, batchID string, _ []TrafficDelta) error {
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
	return nil
}

func TestTrafficReporterPersistsMultipleBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10, Download: 20}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"version"`)) {
		t.Fatalf("single-batch outbox is not readable by 4.2: %s", data)
	}
	firstID := reporter.pending[0].ID
	if len(firstID) != 32 {
		t.Fatalf("batch ID length = %d, want 32", len(firstID))
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 5}, {UserID: 9, Download: 3}}); err != nil {
		t.Fatal(err)
	}
	if len(reporter.pending) != 2 || reporter.pending[1].ID == firstID {
		t.Fatalf("pending batches = %+v, want two distinct batches", reporter.pending)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.pending) != 2 || reloaded.pending[0].ID != firstID {
		t.Fatalf("reloaded batches = %+v", reloaded.pending)
	}
	metrics := reloaded.Metrics(time.Now())
	if metrics.Batches != 2 || metrics.Users != 2 || metrics.Records != 3 || metrics.UploadBytes != 15 || metrics.DownloadBytes != 23 {
		t.Fatalf("unexpected outbox metrics: %+v", metrics)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("outbox permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestTrafficOutboxJSONExactlyMatches42(t *testing.T) {
	batches := []TrafficBatch{
		{
			ID:        "0123456789abcdef0123456789abcdef",
			CreatedAt: 123,
			Deltas:    []TrafficDelta{{UserID: 7, Upload: 10, Download: 20}},
		},
		{
			ID:        "fedcba9876543210fedcba9876543210",
			CreatedAt: 456,
			Deltas:    []TrafficDelta{{UserID: 9, Upload: 30, Download: 40}},
		},
	}
	tests := []struct {
		name    string
		batches []TrafficBatch
		want    string
	}{
		{
			name:    "single batch",
			batches: batches[:1],
			want:    `{"id":"0123456789abcdef0123456789abcdef","createdAt":123,"deltas":[{"UserID":7,"Upload":10,"Download":20}]}`,
		},
		{
			name:    "multiple batches",
			batches: batches,
			want:    `{"version":1,"batches":[{"id":"0123456789abcdef0123456789abcdef","createdAt":123,"deltas":[{"UserID":7,"Upload":10,"Download":20}]},{"id":"fedcba9876543210fedcba9876543210","createdAt":456,"deltas":[{"UserID":9,"Upload":30,"Download":40}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "traffic-outbox.json")
			reporter := &trafficReporter{path: path}
			if _, err := reporter.persist(test.batches); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("outbox JSON differs from 4.2 format:\n got %s\nwant %s", got, test.want)
			}
		})
	}
}

func TestTrafficReporterLoadsLegacyOutbox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	data := []byte(`{"id":"0123456789abcdef0123456789abcdef","deltas":[{"UserID":7,"Upload":10,"Download":20}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reporter.pending) != 1 || reporter.pending[0].CreatedAt <= 0 {
		t.Fatalf("legacy outbox was not migrated in memory: %+v", reporter.pending)
	}
	if dataAfter, err := os.ReadFile(path); err != nil || !bytes.Equal(dataAfter, data) {
		t.Fatalf("legacy outbox was unexpectedly rewritten: data=%q err=%v", dataAfter, err)
	}
}

func TestTrafficReporterUsesFlushTimeBillingContext(t *testing.T) {
	reporter, err := newTrafficReporter(filepath.Join(t.TempDir(), "traffic-outbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	database := &fakeTrafficDatabase{}
	if err := reporter.Flush(database, Node{ID: 999, TrafficRate: 9}); err != nil {
		t.Fatal(err)
	}
	if len(database.nodes) != 1 || database.nodes[0].ID != 999 || database.nodes[0].TrafficRate != 9 {
		t.Fatalf("traffic did not use the 4.2 flush-time billing context: %+v", database.nodes)
	}
}

func TestTrafficReporterRefusesInvalidOutboxUntilManualRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	invalid := []byte(`{"version":1,"batches":[`)
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	reporter, err := newTrafficReporter(path)
	if err == nil || reporter != nil {
		t.Fatalf("invalid outbox did not fail startup: reporter=%v err=%v", reporter, err)
	}
	dataAfter, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataAfter, invalid) {
		t.Fatalf("invalid outbox changed: %q", dataAfter)
	}
	reporter, err = newTrafficReporter(path)
	if err == nil || reporter != nil {
		t.Fatalf("second startup bypassed manual recovery: reporter=%v err=%v", reporter, err)
	}
}

func TestTrafficReporterQueuesWhileDatabaseIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := reporter.Flush(database, Node{ID: 116}); err == nil {
		t.Fatal("flush unexpectedly succeeded")
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Download: 20}}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.pending) != 2 {
		t.Fatalf("pending batches = %d, want 2", len(reloaded.pending))
	}
	database.err = nil
	if err := reloaded.Flush(database, Node{ID: 116}); err != nil {
		t.Fatal(err)
	}
	if len(database.batchIDs) != 2 || database.batchIDs[0] == database.batchIDs[1] {
		t.Fatalf("reported batch IDs = %v", database.batchIDs)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outbox still exists after successful flush: %v", err)
	}
}

func TestFlushClassifiesPostCommitPersistenceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block-removal"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	database := &fakeTrafficDatabase{}
	flushed, err := reportTraffic(database, Node{ID: 116, TrafficRate: 1}, NewState(), reporter, &databaseHealth{})
	if !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("post-commit persistence error = %v, want fatal outbox classification", err)
	}
	if flushed {
		t.Fatal("failed outbox update was reported as a successful flush")
	}
	if len(database.batchIDs) != 1 {
		t.Fatalf("database was not committed before persistence failure: %v", database.batchIDs)
	}
}

func TestFinalTrafficReturnsPostCommitPersistenceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block-removal"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err = reportFinalTraffic(
		&fakeTrafficDatabase{},
		Node{ID: 116, TrafficRate: 1},
		NewState(),
		reporter,
		&databaseHealth{},
		zap.NewNop(),
	)
	if !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("final post-commit persistence error = %v, want fatal outbox classification", err)
	}
}

func TestReportTrafficPersistsNewTrafficAfterBacklogFlushFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState()
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	health := &databaseHealth{}
	state.AddTraffic(7, 100, 0)
	if _, err := reportTraffic(database, Node{ID: 116, TrafficRate: 1}, state, reporter, health); err == nil {
		t.Fatal("first report unexpectedly succeeded")
	}
	state.AddTraffic(7, 0, 200)
	_, secondErr := reportTraffic(database, Node{ID: 116, TrafficRate: 1}, state, reporter, health)
	if !errors.Is(secondErr, database.err) {
		t.Fatalf("second report error = %v, want original database error %v", secondErr, database.err)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("new traffic remained only in memory after backlog flush failed: %+v", metrics)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	metrics := reloaded.Metrics(time.Now())
	if metrics.Batches != 2 || metrics.UploadBytes != 100 || metrics.DownloadBytes != 200 {
		t.Fatalf("new traffic was not persisted as a separate durable batch: %+v", metrics)
	}
	if reloaded.pending[0].ID == reloaded.pending[1].ID ||
		len(reloaded.pending[0].Deltas) != 1 ||
		len(reloaded.pending[1].Deltas) != 1 ||
		reloaded.pending[0].Deltas[0].Upload != 100 ||
		reloaded.pending[0].Deltas[0].Download != 0 ||
		reloaded.pending[1].Deltas[0].Upload != 0 ||
		reloaded.pending[1].Deltas[0].Download != 200 {
		t.Fatalf("unexpected durable batch boundaries: %+v", reloaded.pending)
	}
	wantIDs := []string{reloaded.pending[0].ID, reloaded.pending[1].ID}

	database.err = nil
	if _, err := reportTraffic(database, Node{ID: 116, TrafficRate: 1}, state, reloaded, health); err != nil {
		t.Fatal(err)
	}
	if len(database.batchIDs) != 2 || database.batchIDs[0] != wantIDs[0] || database.batchIDs[1] != wantIDs[1] {
		t.Fatalf("reported batch IDs = %v, want %v", database.batchIDs, wantIDs)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("traffic remained in memory after recovery: %+v", metrics)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outbox remained after recovery: %v", err)
	}
}

func TestReportTrafficCaptureFailureAfterBacklogFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 100}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block-replacement"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	state := NewState()
	state.AddTraffic(7, 0, 200)
	databaseErr := errors.New("database unavailable")
	_, err = reportTraffic(
		&fakeTrafficDatabase{err: databaseErr},
		Node{ID: 116, TrafficRate: 1},
		state,
		reporter,
		&databaseHealth{},
	)
	if !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("capture error = %v, want fatal outbox persistence classification", err)
	}
	if errors.Is(err, databaseErr) {
		t.Fatalf("capture failure returned the ordinary database error: %v", err)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 1 || metrics.TrafficDownloadBytes != 200 {
		t.Fatalf("capture failure lost new in-memory traffic: %+v", metrics)
	}
	if len(reporter.pending) != 1 || reporter.pending[0].Deltas[0].Upload != 100 {
		t.Fatalf("existing durable backlog changed after capture failure: %+v", reporter.pending)
	}
}

func TestReportTrafficTreatsCaptureFailureAsFatal(t *testing.T) {
	state := NewState()
	state.AddTraffic(7, 100, 200)
	reporter := &trafficReporter{path: t.TempDir()}
	_, err := reportTraffic(&fakeTrafficDatabase{}, Node{ID: 116, TrafficRate: 1}, state, reporter, &databaseHealth{})
	if !errors.Is(err, errTrafficOutboxPersistence) {
		t.Fatalf("capture error = %v, want fatal outbox persistence error", err)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 1 || metrics.TrafficUploadBytes != 100 || metrics.TrafficDownloadBytes != 200 {
		t.Fatalf("capture failure lost in-memory traffic: %+v", metrics)
	}
}

func TestReportTrafficReportsRecoveryBeforeLaterFailure(t *testing.T) {
	reporter, err := newTrafficReporter(filepath.Join(t.TempDir(), "traffic-outbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10}}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(7, 0, 20)
	laterFailure := errors.New("second flush failed")
	database := &fakeTrafficDatabase{errs: []error{nil, laterFailure}}
	flushed, err := reportTraffic(database, Node{ID: 116, TrafficRate: 1}, state, reporter, &databaseHealth{})
	if !flushed || !errors.Is(err, laterFailure) {
		t.Fatalf("flushed=%v err=%v, want prior recovery followed by new failure", flushed, err)
	}
}

func TestFinalTrafficIsPersistedWhenDatabaseIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 50}}); err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(7, 100, 200)
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	health := &databaseHealth{}
	if err := reportFinalTraffic(database, Node{ID: 116, TrafficRate: 1}, state, reporter, health, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("traffic remained only in memory: %+v", metrics)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	metrics := reloaded.Metrics(time.Now())
	if metrics.Batches != 2 || metrics.UploadBytes != 150 || metrics.DownloadBytes != 200 {
		t.Fatalf("final traffic was not persisted: %+v", metrics)
	}
	if health.Snapshot().Failures != 1 {
		t.Fatalf("database failure was not recorded: %+v", health.Snapshot())
	}
}
