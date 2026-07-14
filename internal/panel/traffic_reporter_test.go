package panel

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeTrafficDatabase struct {
	err      error
	batchIDs []string
}

func (d *fakeTrafficDatabase) ReportTraffic(_ Node, batchID string, _ []TrafficDelta) error {
	if d.err != nil {
		return d.err
	}
	d.batchIDs = append(d.batchIDs, batchID)
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
		t.Fatalf("single-batch outbox is not readable by 4.0: %s", data)
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

func TestReportTrafficPersistsEveryFailedReportingPeriod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState()
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	health := &databaseHealth{}
	state.AddTraffic(7, 100, 0)
	if err := reportTraffic(database, Node{ID: 116}, state, reporter, health); err == nil {
		t.Fatal("first report unexpectedly succeeded")
	}
	state.AddTraffic(7, 0, 200)
	if err := reportTraffic(database, Node{ID: 116}, state, reporter, health); err == nil {
		t.Fatal("second report unexpectedly succeeded")
	}
	if metrics := state.PendingMetrics(); metrics.TrafficUsers != 0 {
		t.Fatalf("failed-period traffic remained only in memory: %+v", metrics)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	metrics := reloaded.Metrics(time.Now())
	if metrics.Batches != 2 || metrics.UploadBytes != 100 || metrics.DownloadBytes != 200 {
		t.Fatalf("failed reporting periods were not independently persisted: %+v", metrics)
	}
}

func TestFinalTrafficIsPersistedWhenDatabaseIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState()
	state.AddTraffic(7, 100, 200)
	database := &fakeTrafficDatabase{err: errors.New("database unavailable")}
	health := &databaseHealth{}
	if err := reportFinalTraffic(database, Node{ID: 116}, state, reporter, health, zap.NewNop()); err != nil {
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
	if metrics.Batches != 1 || metrics.UploadBytes != 100 || metrics.DownloadBytes != 200 {
		t.Fatalf("final traffic was not persisted: %+v", metrics)
	}
	if health.Snapshot().Failures != 1 {
		t.Fatalf("database failure was not recorded: %+v", health.Snapshot())
	}
}
