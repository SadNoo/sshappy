package flyskynode

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/database64128/shadowsocks-go/internal/flyskyapi"
)

const (
	method                 = "2022-blake3-aes-256-gcm"
	keyLen                 = 32
	syncStateSchemaVersion = 3
)

var ErrRestartRequired = errors.New("Flysky node configuration changed; runtime restart is required")
var ErrSynchronizationUnsafe = errors.New("Flysky synchronization commit failed closed; runtime restart is required")
var ErrServingGenerationChanged = errors.New("Flysky serving generation changed; a full snapshot is required")
var ErrStopServingRequested = errors.New("Flysky stop-serving transition requested")

type StopServingRequestError struct {
	ServingGeneration string
}

func (err *StopServingRequestError) Error() string {
	return ErrStopServingRequested.Error()
}

func (err *StopServingRequestError) Unwrap() error {
	return ErrStopServingRequested
}

type ControlPlane interface {
	Snapshot(context.Context, string) (flyskyapi.Snapshot, error)
	Changes(context.Context, string, string) (flyskyapi.Changes, error)
}

type credentialReloader interface {
	LoadFromFile() error
}

type AppliedSnapshot struct {
	Wire      flyskyapi.Snapshot
	ServerKey []byte
	Users     []User
}

type Synchronizer struct {
	control        ControlPlane
	runtime        *Runtime
	reloader       credentialReloader
	credentialPath string
	snapshotPath   string
	syncStatePath  string
	now            func() time.Time
	current        *AppliedSnapshot
	saveSyncState  func(string, flyskyapi.SyncState) error
	saveSnapshot   func(string, flyskyapi.Snapshot) error
}

func NewSynchronizer(
	control ControlPlane,
	runtime *Runtime,
	credentialPath, snapshotPath, syncStatePath string,
) *Synchronizer {
	return &Synchronizer{
		control: control, runtime: runtime,
		credentialPath: credentialPath, snapshotPath: snapshotPath, syncStatePath: syncStatePath,
		now: time.Now, saveSyncState: flyskyapi.SaveSyncState, saveSnapshot: flyskyapi.SaveSnapshot,
	}
}

func (syncer *Synchronizer) SetCredentialReloader(reloader credentialReloader) {
	syncer.reloader = reloader
}

func (syncer *Synchronizer) Current() (AppliedSnapshot, bool) {
	if syncer.current == nil {
		return AppliedSnapshot{}, false
	}
	return cloneApplied(*syncer.current), true
}

func (syncer *Synchronizer) FetchAndInstallSnapshot(ctx context.Context, accessToken, expectedNodeID string) (AppliedSnapshot, error) {
	if syncer.control == nil {
		return AppliedSnapshot{}, errors.New("Flysky control plane is unavailable")
	}
	snapshot, err := syncer.control.Snapshot(ctx, accessToken)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	return syncer.InstallSnapshot(snapshot, expectedNodeID)
}

func (syncer *Synchronizer) InstallSnapshot(snapshot flyskyapi.Snapshot, expectedNodeID string) (AppliedSnapshot, error) {
	if snapshot.StopServingGeneration != "" {
		if !validUUID(snapshot.Node.NodeID) || expectedNodeID != "" && snapshot.Node.NodeID != expectedNodeID ||
			!validUUID(snapshot.StopServingGeneration) || snapshot.StopServingGeneration != snapshot.ServingGeneration {
			return AppliedSnapshot{}, errors.New("Flysky snapshot contains an invalid stop-serving transition")
		}
		if err := syncer.persistStopServingRequested(snapshot.Node.NodeID, snapshot.StopServingGeneration); err != nil {
			return AppliedSnapshot{}, syncer.commitFailure("persist Flysky snapshot stop-serving barrier", err)
		}
		return AppliedSnapshot{}, &StopServingRequestError{ServingGeneration: snapshot.StopServingGeneration}
	}
	stopState, stopExists, err := syncer.LoadStopServingState(expectedNodeID)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	if stopExists && stopState.ServingGeneration == snapshot.ServingGeneration {
		return AppliedSnapshot{}, &StopServingRequestError{ServingGeneration: stopState.ServingGeneration}
	}
	state, _, err := syncer.loadSynchronizationState(expectedNodeID)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	applied, err := validateSnapshotWithResourceVersions(snapshot, expectedNodeID, syncer.now(), state.ResourceVersions)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	if syncer.current != nil && nodeRestartRequired(syncer.current.Wire.Node, snapshot.Node) {
		return AppliedSnapshot{}, ErrRestartRequired
	}
	if err := syncer.commit(applied); err != nil {
		return AppliedSnapshot{}, err
	}
	if stopExists {
		if err := syncer.ClearStopServingState(); err != nil {
			return AppliedSnapshot{}, syncer.commitFailure("clear obsolete Flysky stop-serving barrier", err)
		}
	}
	return cloneApplied(applied), nil
}

func (syncer *Synchronizer) LoadCachedSnapshot(expectedNodeID string) (AppliedSnapshot, error) {
	if _, exists, err := syncer.loadSynchronizationState(expectedNodeID); err != nil {
		return AppliedSnapshot{}, err
	} else if !exists {
		return AppliedSnapshot{}, errors.New("Flysky cached snapshot has no durable synchronization state")
	}
	snapshot, err := flyskyapi.LoadSnapshot(syncer.snapshotPath)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	return syncer.InstallSnapshot(snapshot, expectedNodeID)
}

func (syncer *Synchronizer) PollChanges(ctx context.Context, accessToken string) (AppliedSnapshot, error) {
	if syncer.current == nil {
		return AppliedSnapshot{}, errors.New("Flysky snapshot is not installed")
	}
	changes, err := syncer.control.Changes(ctx, accessToken, syncer.current.Wire.Cursor)
	if err != nil {
		return AppliedSnapshot{}, err
	}
	next, changed, err := applyChanges(syncer.current.Wire, changes, syncer.now())
	if err != nil {
		var stopRequest *StopServingRequestError
		if errors.As(err, &stopRequest) {
			if persistErr := syncer.persistStopServingRequested(syncer.current.Wire.Node.NodeID, stopRequest.ServingGeneration); persistErr != nil {
				return AppliedSnapshot{}, syncer.commitFailure("persist Flysky stop-serving barrier", persistErr)
			}
		}
		return AppliedSnapshot{}, err
	}
	if !changed {
		return cloneApplied(*syncer.current), nil
	}
	applied, err := validateSnapshot(next, syncer.current.Wire.Node.NodeID, syncer.now())
	if err != nil {
		return AppliedSnapshot{}, err
	}
	if err := syncer.commit(applied); err != nil {
		return AppliedSnapshot{}, err
	}
	return cloneApplied(applied), nil
}

func (syncer *Synchronizer) commit(applied AppliedSnapshot) error {
	previous, _, err := syncer.loadSynchronizationState(applied.Wire.Node.NodeID)
	if err != nil {
		return syncer.commitFailure("load Flysky synchronization state", err)
	}
	now := syncer.now().UTC()
	// Persist authorization high-water marks before touching credentials or the
	// runtime. The previously acknowledged generation/cursor are deliberately
	// preserved here: a response that is merely fetched, or an install that
	// crashes/fails midway, must never be acknowledged as applied.
	fenceState := flyskyapi.SyncState{
		NodeID: applied.Wire.Node.NodeID, SchemaVersion: syncStateSchemaVersion, UpdatedAt: now,
		ResourceVersions: cloneResourceVersions(applied.Wire.ResourceVersions),
	}
	if previous.SchemaVersion == syncStateSchemaVersion && previous.AppliedServingGeneration != "" {
		fenceState.AppliedServingGeneration = previous.AppliedServingGeneration
		fenceState.ConfigVersion = previous.ConfigVersion
		fenceState.Cursor = previous.Cursor
		fenceState.SnapshotValidUntil = previous.SnapshotValidUntil
	}
	if err := syncer.saveSyncState(syncer.syncStatePath, fenceState); err != nil {
		return syncer.commitFailure("persist Flysky authorization fences", err)
	}
	if err := writeCredentials(syncer.credentialPath, applied.Users); err != nil {
		return syncer.commitFailure("persist Flysky SS2022 credentials", err)
	}
	if syncer.reloader != nil {
		if err := syncer.reloader.LoadFromFile(); err != nil {
			return syncer.commitFailure("activate Flysky SS2022 credentials", err)
		}
	}
	syncer.runtime.ReplaceUsers(applied.Wire.ValidUntil, applied.Users)
	if err := syncer.saveSnapshot(syncer.snapshotPath, applied.Wire); err != nil {
		return syncer.commitFailure("persist Flysky snapshot", err)
	}
	// This second atomic state replacement is the acknowledgement commit point.
	// It is intentionally last: only a fully validated, activated, and durable
	// snapshot/delta may advance the generation and cursor reported in heartbeat.
	acknowledgedState := flyskyapi.SyncState{
		NodeID: applied.Wire.Node.NodeID, SchemaVersion: syncStateSchemaVersion,
		AppliedServingGeneration: applied.Wire.ServingGeneration,
		ConfigVersion:            applied.Wire.ConfigVersion, Cursor: applied.Wire.Cursor,
		SnapshotValidUntil: applied.Wire.ValidUntil, UpdatedAt: now,
		ResourceVersions: cloneResourceVersions(applied.Wire.ResourceVersions),
	}
	if err := syncer.saveSyncState(syncer.syncStatePath, acknowledgedState); err != nil {
		return syncer.commitFailure("persist Flysky applied generation acknowledgement", err)
	}
	next := cloneApplied(applied)
	syncer.current = &next
	return nil
}

func (syncer *Synchronizer) commitFailure(operation string, cause error) error {
	invalidationErr := syncer.failClosed()
	return errors.Join(ErrSynchronizationUnsafe, fmt.Errorf("%s: %w", operation, cause), invalidationErr)
}

func (syncer *Synchronizer) failClosed() error {
	// Runtime policy enforcement is authoritative after credential lookup. Clear
	// it first so old credentials and already-open sessions cannot survive a
	// partial durable commit. Replacing the credential file is best effort: a
	// broken path or reloader must not prevent the in-memory authorization fence.
	syncer.runtime.ReplaceUsers(time.Time{}, nil)
	syncer.current = nil
	var invalidationErr error
	if err := writeCredentials(syncer.credentialPath, nil); err == nil && syncer.reloader != nil {
		invalidationErr = errors.Join(invalidationErr, syncer.reloader.LoadFromFile())
	} else if err != nil {
		invalidationErr = errors.Join(invalidationErr, fmt.Errorf("clear Flysky credentials: %w", err))
	}
	invalidationErr = errors.Join(invalidationErr, removePrivateState(syncer.snapshotPath), removePrivateState(syncer.credentialPath))
	return invalidationErr
}

func (syncer *Synchronizer) LoadStopServingState(expectedNodeID string) (flyskyapi.StopServingState, bool, error) {
	state, err := flyskyapi.LoadStopServingState(syncer.stopServingStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return flyskyapi.StopServingState{}, false, nil
	}
	if err != nil {
		return flyskyapi.StopServingState{}, false, fmt.Errorf("load Flysky stop-serving state: %w", err)
	}
	if expectedNodeID != "" && state.NodeID != expectedNodeID {
		return flyskyapi.StopServingState{}, false, errors.New("Flysky stop-serving state belongs to a different node")
	}
	return state, true, nil
}

func (syncer *Synchronizer) persistStopServingRequested(nodeID, generation string) error {
	if !validUUID(nodeID) || !validUUID(generation) {
		return errors.New("invalid Flysky stop-serving identity")
	}
	state, exists, err := syncer.LoadStopServingState(nodeID)
	if err != nil {
		return err
	}
	if exists {
		if state.ServingGeneration != generation {
			return errors.New("Flysky stop-serving generation conflicts with its durable barrier")
		}
		return nil
	}
	return flyskyapi.SaveStopServingState(syncer.stopServingStatePath(), flyskyapi.StopServingState{
		NodeID: nodeID, ServingGeneration: generation, Phase: "requested", UpdatedAt: syncer.now().UTC(),
	})
}

func (syncer *Synchronizer) CompleteStopServing(nodeID, generation string) error {
	state, exists, err := syncer.LoadStopServingState(nodeID)
	if err != nil {
		return err
	}
	if !exists || state.ServingGeneration != generation {
		return errors.New("Flysky stop-serving completion has no matching durable barrier")
	}
	if syncer.current != nil && syncer.current.Wire.ServingGeneration != generation {
		return errors.New("Flysky stop-serving generation does not match the active runtime")
	}
	// The listener must already be stopped by the runner. This method then
	// removes every credential/cache path under a durable requested barrier;
	// only the final state replacement makes the stopped ACK reportable.
	syncer.runtime.ReplaceUsers(time.Time{}, nil)
	syncer.current = nil
	if err := writeCredentials(syncer.credentialPath, nil); err != nil {
		return fmt.Errorf("clear Flysky stop-serving credentials: %w", err)
	}
	if syncer.reloader != nil {
		if err := syncer.reloader.LoadFromFile(); err != nil {
			return fmt.Errorf("activate empty Flysky stop-serving credentials: %w", err)
		}
	}
	if err := errors.Join(
		removePrivateState(syncer.snapshotPath),
		removePrivateState(syncer.syncStatePath),
		removePrivateState(syncer.credentialPath),
	); err != nil {
		return err
	}
	return flyskyapi.SaveStopServingState(syncer.stopServingStatePath(), flyskyapi.StopServingState{
		NodeID: nodeID, ServingGeneration: generation, Phase: "stopped", UpdatedAt: syncer.now().UTC(),
	})
}

func (syncer *Synchronizer) ClearStopServingState() error {
	return removePrivateState(syncer.stopServingStatePath())
}

func (syncer *Synchronizer) stopServingStatePath() string {
	return syncer.syncStatePath + ".stop-serving"
}

func (syncer *Synchronizer) loadSynchronizationState(expectedNodeID string) (flyskyapi.SyncState, bool, error) {
	state, err := flyskyapi.LoadSyncState(syncer.syncStatePath)
	if errors.Is(err, os.ErrNotExist) {
		return flyskyapi.SyncState{}, false, nil
	}
	if err != nil {
		return flyskyapi.SyncState{}, false, fmt.Errorf("load Flysky synchronization state: %w", err)
	}
	if expectedNodeID != "" && state.NodeID != expectedNodeID {
		return flyskyapi.SyncState{}, false, errors.New("Flysky synchronization state belongs to a different node")
	}
	state.ResourceVersions = cloneResourceVersions(state.ResourceVersions)
	return state, true, nil
}

func validateSnapshot(snapshot flyskyapi.Snapshot, expectedNodeID string, now time.Time) (AppliedSnapshot, error) {
	return validateSnapshotWithResourceVersions(snapshot, expectedNodeID, now, nil)
}

func validateSnapshotWithResourceVersions(
	snapshot flyskyapi.Snapshot,
	expectedNodeID string,
	now time.Time,
	baseline map[string]int64,
) (AppliedSnapshot, error) {
	if snapshot.SchemaVersion != 1 {
		return AppliedSnapshot{}, fmt.Errorf("unsupported Flysky snapshot schema version %d", snapshot.SchemaVersion)
	}
	if !validUUID(snapshot.ServingGeneration) {
		return AppliedSnapshot{}, errors.New("Flysky snapshot is missing a valid serving generation")
	}
	if snapshot.StopServingGeneration != "" {
		return AppliedSnapshot{}, errors.New("Flysky stop-serving snapshot cannot be activated")
	}
	if strings.TrimSpace(snapshot.ConfigVersion) == "" || strings.TrimSpace(snapshot.Cursor) == "" {
		return AppliedSnapshot{}, errors.New("Flysky snapshot is missing config version or cursor")
	}
	if snapshot.GeneratedAt.IsZero() || snapshot.ValidUntil.IsZero() || !snapshot.ValidUntil.After(snapshot.GeneratedAt) {
		return AppliedSnapshot{}, errors.New("Flysky snapshot validity window is invalid")
	}
	if snapshot.GeneratedAt.After(now.Add(5 * time.Minute)) {
		return AppliedSnapshot{}, errors.New("Flysky snapshot generation time is too far in the future")
	}
	if !now.Before(snapshot.ValidUntil) {
		return AppliedSnapshot{}, errors.New("Flysky snapshot has expired")
	}
	node := snapshot.Node
	if !validUUID(node.NodeID) || expectedNodeID != "" && node.NodeID != expectedNodeID {
		return AppliedSnapshot{}, errors.New("Flysky snapshot node identity does not match the machine credential")
	}
	if node.Protocol != "ss2022" || node.Method != method || node.ListenPort < 1 || node.ListenPort > 65535 || node.ServerSecretVersion < 1 {
		return AppliedSnapshot{}, errors.New("Flysky snapshot contains an unsupported node configuration")
	}
	serverKey, err := decodeKey(node.ServerKey)
	if err != nil {
		return AppliedSnapshot{}, fmt.Errorf("invalid Flysky SS2022 server key: %w", err)
	}

	if snapshot.ResourceVersions == nil {
		return AppliedSnapshot{}, errors.New("Flysky snapshot is missing resource version fences")
	}
	if len(snapshot.Users) > flyskyapi.MaxSnapshotUsers || len(snapshot.ResourceVersions) > flyskyapi.MaxResourceVersionFences {
		return AppliedSnapshot{}, errors.New("Flysky snapshot contains too many resources")
	}
	snapshotResourceVersions := cloneResourceVersions(snapshot.ResourceVersions)
	resourceVersions := cloneResourceVersions(snapshot.ResourceVersions)
	for resourceID, version := range baseline {
		if version > resourceVersions[resourceID] {
			resourceVersions[resourceID] = version
		}
	}
	if len(resourceVersions) > flyskyapi.MaxResourceVersionFences {
		return AppliedSnapshot{}, errors.New("Flysky snapshot and persisted fence union contains too many resources")
	}
	for resourceID, version := range resourceVersions {
		if !validUUID(resourceID) || version < 1 {
			return AppliedSnapshot{}, errors.New("Flysky snapshot contains an invalid resource version fence")
		}
	}

	users := make([]User, 0, len(snapshot.Users))
	wireUsers := make([]flyskyapi.SnapshotUser, 0, len(snapshot.Users))
	seenUsers := make(map[string]struct{}, len(snapshot.Users))
	seenKeys := make(map[string]string, len(snapshot.Users))
	for _, wireUser := range snapshot.Users {
		if !validUUID(wireUser.UserID) || wireUser.CredentialVersion < 1 || wireUser.PolicyVersion < 1 ||
			wireUser.ValidUntil.IsZero() || wireUser.QuotaRemainingBytes < 0 {
			return AppliedSnapshot{}, errors.New("Flysky snapshot contains an invalid SS2022 user")
		}
		if _, exists := seenUsers[wireUser.UserID]; exists {
			return AppliedSnapshot{}, fmt.Errorf("Flysky snapshot contains duplicate user %s", wireUser.UserID)
		}
		seenUsers[wireUser.UserID] = struct{}{}
		key, err := decodeKey(wireUser.UserKey)
		if err != nil {
			return AppliedSnapshot{}, fmt.Errorf("invalid Flysky SS2022 user key for %s: %w", wireUser.UserID, err)
		}
		snapshotResourceVersion := snapshotResourceVersions[wireUser.UserID]
		if snapshotResourceVersion < 1 {
			return AppliedSnapshot{}, errors.New("Flysky snapshot user is missing its resource version fence")
		}
		if snapshotResourceVersion < resourceVersions[wireUser.UserID] {
			// A locally persisted fence is newer than this snapshot entry. Keep the
			// resource unavailable until the control plane supplies a newer version.
			continue
		}
		if wireUser.PolicyVersion != snapshotResourceVersion {
			return AppliedSnapshot{}, errors.New("Flysky snapshot user policy version does not match its resource version fence")
		}
		fingerprint := base64.RawStdEncoding.EncodeToString(key)
		if other, exists := seenKeys[fingerprint]; exists {
			return AppliedSnapshot{}, fmt.Errorf("Flysky snapshot reuses one SS2022 key for users %s and %s", other, wireUser.UserID)
		}
		seenKeys[fingerprint] = wireUser.UserID
		wireUsers = append(wireUsers, wireUser)
		if !now.Before(wireUser.ValidUntil) || !wireUser.Unlimited && wireUser.QuotaRemainingBytes == 0 {
			continue
		}
		users = append(users, User{
			ID: wireUser.UserID, CredentialVersion: wireUser.CredentialVersion, Key: key,
			ValidUntil: wireUser.ValidUntil, Unlimited: wireUser.Unlimited, QuotaRemainingBytes: wireUser.QuotaRemainingBytes,
			PolicyVersion: wireUser.PolicyVersion,
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	sort.Slice(wireUsers, func(i, j int) bool { return wireUsers[i].UserID < wireUsers[j].UserID })
	snapshot.Users = wireUsers
	snapshot.ResourceVersions = resourceVersions
	return AppliedSnapshot{Wire: cloneSnapshot(snapshot), ServerKey: serverKey, Users: users}, nil
}

func applyChanges(current flyskyapi.Snapshot, set flyskyapi.Changes, now time.Time) (flyskyapi.Snapshot, bool, error) {
	if !validUUID(set.ServingGeneration) || set.ServingGeneration != current.ServingGeneration {
		return flyskyapi.Snapshot{}, false, ErrServingGenerationChanged
	}
	if strings.TrimSpace(set.NextCursor) == "" {
		return flyskyapi.Snapshot{}, false, errors.New("Flysky changes response is missing next cursor")
	}
	if len(set.Changes) > flyskyapi.MaxIncrementalChanges {
		return flyskyapi.Snapshot{}, false, errors.New("Flysky changes response contains too many records")
	}
	if len(current.Users) > flyskyapi.MaxSnapshotUsers || len(current.ResourceVersions) > flyskyapi.MaxResourceVersionFences {
		return flyskyapi.Snapshot{}, false, errors.New("Flysky current snapshot contains too many resources")
	}
	var previousSequence int64
	for index, change := range set.Changes {
		if change.Sequence < 1 || index > 0 && change.Sequence <= previousSequence || change.ResourceVersion < 1 || !validUUID(change.ResourceID) {
			return flyskyapi.Snapshot{}, false, errors.New("Flysky changes response is unordered or invalid")
		}
		previousSequence = change.Sequence
		if change.Operation != "stop_serving" {
			continue
		}
		var payload struct {
			ServingGeneration string `json:"serving_generation"`
		}
		if err := decodeStrictJSON(change.Payload, &payload); err != nil {
			return flyskyapi.Snapshot{}, false, fmt.Errorf("decode Flysky stop_serving payload: %w", err)
		}
		if change.ResourceID != current.Node.NodeID || payload.ServingGeneration != current.ServingGeneration {
			return flyskyapi.Snapshot{}, false, errors.New("Flysky stop_serving identity or generation does not match the active node")
		}
		return flyskyapi.Snapshot{}, false, &StopServingRequestError{ServingGeneration: payload.ServingGeneration}
	}
	if len(set.Changes) == 0 && set.NextCursor == current.Cursor {
		return current, false, nil
	}
	next := cloneSnapshot(current)
	resourceVersions := cloneResourceVersions(next.ResourceVersions)
	users := make(map[string]flyskyapi.SnapshotUser, len(next.Users))
	for _, user := range next.Users {
		users[user.UserID] = user
	}
	for _, change := range set.Changes {
		switch change.Operation {
		case "upsert_user":
			if change.ResourceVersion <= resourceVersions[change.ResourceID] {
				continue
			}
			var user flyskyapi.SnapshotUser
			if err := decodeStrictJSON(change.Payload, &user); err != nil {
				return flyskyapi.Snapshot{}, false, fmt.Errorf("decode Flysky upsert_user payload: %w", err)
			}
			if user.UserID != change.ResourceID {
				return flyskyapi.Snapshot{}, false, errors.New("Flysky upsert_user resource identity does not match its payload")
			}
			if user.PolicyVersion != change.ResourceVersion {
				return flyskyapi.Snapshot{}, false, errors.New("Flysky upsert_user policy version does not match its resource version")
			}
			users[user.UserID] = user
			resourceVersions[user.UserID] = change.ResourceVersion
		case "revoke_user":
			if change.ResourceVersion <= resourceVersions[change.ResourceID] {
				continue
			}
			var payload struct {
				UserID string `json:"user_id"`
			}
			if err := decodeStrictJSON(change.Payload, &payload); err != nil {
				return flyskyapi.Snapshot{}, false, fmt.Errorf("decode Flysky revoke_user payload: %w", err)
			}
			if payload.UserID != change.ResourceID {
				return flyskyapi.Snapshot{}, false, errors.New("Flysky revoke_user resource identity does not match its payload")
			}
			delete(users, payload.UserID)
			resourceVersions[payload.UserID] = change.ResourceVersion
		case "update_node", "rotate_secret":
			return flyskyapi.Snapshot{}, false, ErrRestartRequired
		default:
			return flyskyapi.Snapshot{}, false, fmt.Errorf("unsupported Flysky node change operation %q", change.Operation)
		}
	}
	if len(users) > flyskyapi.MaxSnapshotUsers || len(resourceVersions) > flyskyapi.MaxResourceVersionFences {
		return flyskyapi.Snapshot{}, false, errors.New("Flysky changes exceed resource limits")
	}
	next.Users = make([]flyskyapi.SnapshotUser, 0, len(users))
	for _, user := range users {
		next.Users = append(next.Users, user)
	}
	sort.Slice(next.Users, func(i, j int) bool { return next.Users[i].UserID < next.Users[j].UserID })
	next.Cursor = set.NextCursor
	next.GeneratedAt = now.UTC()
	next.ResourceVersions = resourceVersions
	return next, true, nil
}

func writeCredentials(path string, users []User) error {
	credentials := make(map[string][]byte, len(users))
	for _, user := range users {
		credentials[credentialLabel(user)] = user.Key
	}
	data, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".flysky-credentials-*")
	if err != nil {
		return err
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
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	committed = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removePrivateState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Flysky fail-closed state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("Flysky fail-closed state path is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove Flysky fail-closed state: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open Flysky fail-closed state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Flysky fail-closed state directory: %w", err)
	}
	return nil
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != keyLen || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("key must be canonical Base64 encoding of exactly 32 bytes")
	}
	return decoded, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("payload must contain exactly one JSON value")
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return true
}

func nodeRestartRequired(current, next flyskyapi.SnapshotNode) bool {
	return current.NodeID != next.NodeID || current.Protocol != next.Protocol || current.Method != next.Method ||
		current.ListenPort != next.ListenPort || current.ServerSecretVersion != next.ServerSecretVersion || current.ServerKey != next.ServerKey
}

func cloneSnapshot(snapshot flyskyapi.Snapshot) flyskyapi.Snapshot {
	cloned := snapshot
	cloned.Users = append([]flyskyapi.SnapshotUser(nil), snapshot.Users...)
	cloned.ResourceVersions = cloneResourceVersions(snapshot.ResourceVersions)
	return cloned
}

func cloneResourceVersions(versions map[string]int64) map[string]int64 {
	cloned := make(map[string]int64, len(versions))
	for resourceID, version := range versions {
		cloned[resourceID] = version
	}
	return cloned
}

func cloneApplied(applied AppliedSnapshot) AppliedSnapshot {
	cloned := applied
	cloned.Wire = cloneSnapshot(applied.Wire)
	cloned.ServerKey = append([]byte(nil), applied.ServerKey...)
	cloned.Users = make([]User, len(applied.Users))
	copy(cloned.Users, applied.Users)
	for index := range cloned.Users {
		cloned.Users[index].Key = append([]byte(nil), applied.Users[index].Key...)
	}
	return cloned
}
