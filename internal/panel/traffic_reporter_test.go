package panel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrafficReporterPersistsAndMergesBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-outbox.json")
	reporter, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 10, Download: 20}}); err != nil {
		t.Fatal(err)
	}
	firstID := reporter.pending.ID
	if len(firstID) != 32 {
		t.Fatalf("batch ID length = %d, want 32", len(firstID))
	}
	if err := reporter.Capture([]TrafficDelta{{UserID: 7, Upload: 5}, {UserID: 9, Download: 3}}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newTrafficReporter(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.pending.ID != firstID {
		t.Fatalf("reloaded batch ID = %q, want %q", reloaded.pending.ID, firstID)
	}
	if len(reloaded.pending.Deltas) != 2 {
		t.Fatalf("reloaded deltas = %d, want 2", len(reloaded.pending.Deltas))
	}
	var upload, download int64
	for _, delta := range reloaded.pending.Deltas {
		if delta.UserID == 7 {
			upload = delta.Upload
			download = delta.Download
		}
	}
	if upload != 15 || download != 20 {
		t.Fatalf("merged user 7 traffic = %d/%d, want 15/20", upload, download)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("outbox permissions = %v, want 0600", info.Mode().Perm())
	}
}
