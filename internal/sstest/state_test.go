package sstest

import "testing"

func TestMergeTrafficRestoresSnapshot(t *testing.T) {
	state := NewRuntimeState()
	state.AddTraffic(7, 10, 20)
	snapshot := state.SnapshotTraffic()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot len = %d", len(snapshot))
	}
	state.MergeTraffic(snapshot)
	restored := state.SnapshotTraffic()
	if len(restored) != 1 {
		t.Fatalf("restored len = %d", len(restored))
	}
	if restored[0].UserID != 7 || restored[0].Upload != 10 || restored[0].Download != 20 {
		t.Fatalf("restored traffic = %#v", restored[0])
	}
}
