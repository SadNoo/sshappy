package panel

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const trafficOutboxVersion = 1

type trafficDatabase interface {
	ReportTraffic(node Node, batchID string, traffic []TrafficDelta) error
}

type trafficOutbox struct {
	Version int            `json:"version"`
	Batches []TrafficBatch `json:"batches"`
}

type trafficOutboxMetrics struct {
	Batches       int
	Users         int
	Records       int
	UploadBytes   int64
	DownloadBytes int64
	FileBytes     int64
	OldestAge     time.Duration
}

type trafficReporter struct {
	path      string
	pending   []TrafficBatch
	fileBytes int64
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat traffic outbox: %w", err)
	}
	batches, err := decodeTrafficOutbox(data, info.ModTime())
	if err != nil {
		return nil, err
	}
	reporter.pending = batches
	reporter.fileBytes = int64(len(data))
	return reporter, nil
}

func decodeTrafficOutbox(data []byte, fallbackCreatedAt time.Time) ([]TrafficBatch, error) {
	var probe struct {
		Version int             `json:"version"`
		Batches json.RawMessage `json:"batches"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("failed to decode traffic outbox: %w", err)
	}

	var batches []TrafficBatch
	if probe.Batches != nil {
		if probe.Version != trafficOutboxVersion {
			return nil, fmt.Errorf("unsupported traffic outbox version %d", probe.Version)
		}
		if err := json.Unmarshal(probe.Batches, &batches); err != nil {
			return nil, fmt.Errorf("failed to decode traffic outbox batches: %w", err)
		}
	} else {
		// Version 3.4 through 4.0 persisted one TrafficBatch directly.
		var batch TrafficBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("failed to decode legacy traffic outbox: %w", err)
		}
		batches = []TrafficBatch{batch}
	}
	if len(batches) == 0 {
		return nil, errors.New("traffic outbox contains no batches")
	}

	seen := make(map[string]struct{}, len(batches))
	for i := range batches {
		batch := &batches[i]
		if batch.CreatedAt == 0 {
			batch.CreatedAt = fallbackCreatedAt.Unix()
		}
		if err := validateTrafficBatch(*batch); err != nil {
			return nil, fmt.Errorf("invalid traffic outbox batch %d: %w", i, err)
		}
		if _, ok := seen[batch.ID]; ok {
			return nil, fmt.Errorf("invalid traffic outbox batch %d: duplicate batch ID", i)
		}
		seen[batch.ID] = struct{}{}
	}
	return batches, nil
}

func validateTrafficBatch(batch TrafficBatch) error {
	if len(batch.ID) != 32 || len(batch.Deltas) == 0 || batch.CreatedAt <= 0 {
		return errors.New("missing ID, creation time, or traffic deltas")
	}
	for _, delta := range batch.Deltas {
		if delta.UserID <= 0 || delta.Upload < 0 || delta.Download < 0 || delta.Upload == 0 && delta.Download == 0 {
			return fmt.Errorf("invalid traffic delta for user %d", delta.UserID)
		}
	}
	return nil
}

func (r *trafficReporter) Capture(deltas []TrafficDelta) error {
	if len(deltas) == 0 {
		return nil
	}

	id, err := newTrafficBatchID()
	if err != nil {
		return err
	}
	next := TrafficBatch{
		ID:        id,
		CreatedAt: time.Now().Unix(),
		Deltas:    mergeTrafficDeltas(deltas),
	}
	if err := validateTrafficBatch(next); err != nil {
		return err
	}
	batches := make([]TrafficBatch, len(r.pending), len(r.pending)+1)
	copy(batches, r.pending)
	batches = append(batches, next)
	fileBytes, err := r.persist(batches)
	if err != nil {
		return err
	}
	r.pending = batches
	r.fileBytes = fileBytes
	return nil
}

func (r *trafficReporter) Flush(db trafficDatabase, node Node) error {
	for len(r.pending) > 0 {
		batch := r.pending[0]
		if err := db.ReportTraffic(node, batch.ID, batch.Deltas); err != nil {
			return err
		}
		next := r.pending[1:]
		fileBytes, err := r.persist(next)
		if err != nil {
			return fmt.Errorf("traffic batch committed but outbox update failed: %w", err)
		}
		r.pending = next
		r.fileBytes = fileBytes
	}
	return nil
}

func (r *trafficReporter) PendingUsers() int {
	return r.Metrics(time.Now()).Users
}

func (r *trafficReporter) Metrics(now time.Time) trafficOutboxMetrics {
	metrics := trafficOutboxMetrics{
		Batches:   len(r.pending),
		FileBytes: r.fileBytes,
	}
	users := make(map[int]struct{})
	for _, batch := range r.pending {
		if createdAt := time.Unix(batch.CreatedAt, 0); !createdAt.After(now) {
			age := now.Sub(createdAt)
			if age > metrics.OldestAge {
				metrics.OldestAge = age
			}
		}
		for _, delta := range batch.Deltas {
			users[delta.UserID] = struct{}{}
			metrics.Records++
			metrics.UploadBytes += delta.Upload
			metrics.DownloadBytes += delta.Download
		}
	}
	metrics.Users = len(users)
	return metrics
}

func (r *trafficReporter) persist(batches []TrafficBatch) (int64, error) {
	if len(batches) == 0 {
		if err := removeFileAtomic(r.path); err != nil {
			return r.fileBytes, err
		}
		return 0, nil
	}
	var value any = trafficOutbox{Version: trafficOutboxVersion, Batches: batches}
	if len(batches) == 1 {
		// Keep the common case readable by 4.0 so a healthy-node rollback does
		// not require manual outbox conversion.
		value = batches[0]
	}
	data, err := json.Marshal(value)
	if err != nil {
		return r.fileBytes, fmt.Errorf("failed to encode traffic outbox: %w", err)
	}
	if err := writeFileAtomic(r.path, data, 0600); err != nil {
		return r.fileBytes, fmt.Errorf("failed to persist traffic outbox: %w", err)
	}
	return int64(len(data)), nil
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
