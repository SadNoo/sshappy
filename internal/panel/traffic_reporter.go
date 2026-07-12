package panel

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type trafficReporter struct {
	path    string
	pending *TrafficBatch
}

func newTrafficReporter(path string) (*trafficReporter, error) {
	reporter := &trafficReporter{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return reporter, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read traffic outbox: %w", err)
	}
	var batch TrafficBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return nil, fmt.Errorf("failed to decode traffic outbox: %w", err)
	}
	if batch.ID == "" || len(batch.Deltas) == 0 {
		return nil, errors.New("traffic outbox contains an invalid batch")
	}
	reporter.pending = &batch
	return reporter, nil
}

func (r *trafficReporter) Capture(deltas []TrafficDelta) error {
	if len(deltas) == 0 {
		return nil
	}

	next := TrafficBatch{}
	if r.pending == nil {
		id, err := newTrafficBatchID()
		if err != nil {
			return err
		}
		next.ID = id
	} else {
		next.ID = r.pending.ID
		next.Deltas = append(next.Deltas, r.pending.Deltas...)
	}
	next.Deltas = mergeTrafficDeltas(next.Deltas, deltas)

	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("failed to encode traffic outbox: %w", err)
	}
	if err := writeFileAtomic(r.path, data, 0600); err != nil {
		return fmt.Errorf("failed to persist traffic outbox: %w", err)
	}
	r.pending = &next
	return nil
}

func (r *trafficReporter) Flush(db *Database, node Node) error {
	if r.pending == nil {
		return nil
	}
	if err := db.ReportTraffic(node, r.pending.ID, r.pending.Deltas); err != nil {
		return err
	}
	if err := os.Remove(r.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("traffic batch committed but outbox removal failed: %w", err)
	}
	r.pending = nil
	return nil
}

func (r *trafficReporter) PendingUsers() int {
	if r.pending == nil {
		return 0
	}
	return len(r.pending.Deltas)
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
