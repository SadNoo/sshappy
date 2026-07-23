package flyskyapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxStateBytes = 64 << 10

type SyncState struct {
	NodeID             string    `json:"node_id"`
	SchemaVersion      int       `json:"schema_version"`
	ConfigVersion      string    `json:"config_version"`
	Cursor             string    `json:"cursor"`
	SnapshotValidUntil time.Time `json:"snapshot_valid_until"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func SaveMachineCredential(path string, credential MachineCredential) error {
	if err := validateMachineCredential(credential); err != nil {
		return err
	}
	return writeState(path, credential)
}

func LoadMachineCredential(path string) (MachineCredential, error) {
	var credential MachineCredential
	if err := readState(path, &credential); err != nil {
		return MachineCredential{}, err
	}
	if err := validateMachineCredential(credential); err != nil {
		return MachineCredential{}, err
	}
	return credential, nil
}

func SaveSyncState(path string, state SyncState) error {
	if err := validateSyncState(state); err != nil {
		return err
	}
	return writeState(path, state)
}

func LoadSyncState(path string) (SyncState, error) {
	var state SyncState
	if err := readState(path, &state); err != nil {
		return SyncState{}, err
	}
	if err := validateSyncState(state); err != nil {
		return SyncState{}, err
	}
	return state, nil
}

func SaveSnapshot(path string, snapshot Snapshot) error {
	if err := validateSnapshotState(snapshot); err != nil {
		return err
	}
	return writeState(path, snapshot)
}

func LoadSnapshot(path string) (Snapshot, error) {
	var snapshot Snapshot
	if err := readState(path, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshotState(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func validateMachineCredential(credential MachineCredential) error {
	if strings.TrimSpace(credential.NodeID) == "" || strings.TrimSpace(credential.AccessToken) == "" ||
		credential.TokenType != "Bearer" || credential.ExpiresAt.IsZero() {
		return errors.New("invalid Flysky machine credential state")
	}
	return nil
}

func validateSyncState(state SyncState) error {
	if strings.TrimSpace(state.NodeID) == "" || state.SchemaVersion < 1 ||
		strings.TrimSpace(state.ConfigVersion) == "" || strings.TrimSpace(state.Cursor) == "" ||
		state.SnapshotValidUntil.IsZero() || state.UpdatedAt.IsZero() {
		return errors.New("invalid Flysky synchronization state")
	}
	return nil
}

func validateSnapshotState(snapshot Snapshot) error {
	if snapshot.SchemaVersion < 1 || strings.TrimSpace(snapshot.ConfigVersion) == "" ||
		strings.TrimSpace(snapshot.Cursor) == "" || snapshot.GeneratedAt.IsZero() || snapshot.ValidUntil.IsZero() ||
		strings.TrimSpace(snapshot.Node.NodeID) == "" || strings.TrimSpace(snapshot.Node.ServerKey) == "" {
		return errors.New("invalid Flysky snapshot state")
	}
	return nil
}

func writeState(path string, value any) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("Flysky state path is required")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode Flysky state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create Flysky state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".flysky-state-*")
	if err != nil {
		return fmt.Errorf("create Flysky temporary state: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("protect Flysky temporary state: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write Flysky temporary state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync Flysky temporary state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close Flysky temporary state: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace Flysky state: %w", err)
	}
	committed = true
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open Flysky state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Flysky state directory: %w", err)
	}
	return nil
}

func readState(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Flysky state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("Flysky state must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("Flysky state permissions must not grant group or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Flysky state: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return fmt.Errorf("read Flysky state: %w", err)
	}
	if len(data) > maxStateBytes {
		return errors.New("Flysky state is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode Flysky state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Flysky state must contain exactly one JSON value")
	}
	return nil
}
