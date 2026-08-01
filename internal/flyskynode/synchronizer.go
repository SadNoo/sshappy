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
	method = "2022-blake3-aes-256-gcm"
	keyLen = 32
)

var ErrRestartRequired = errors.New("Flysky node configuration changed; runtime restart is required")

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
}

func NewSynchronizer(
	control ControlPlane,
	runtime *Runtime,
	credentialPath, snapshotPath, syncStatePath string,
) *Synchronizer {
	return &Synchronizer{
		control: control, runtime: runtime,
		credentialPath: credentialPath, snapshotPath: snapshotPath, syncStatePath: syncStatePath,
		now: time.Now,
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
	applied, err := validateSnapshot(snapshot, expectedNodeID, syncer.now())
	if err != nil {
		return AppliedSnapshot{}, err
	}
	if syncer.current != nil && nodeRestartRequired(syncer.current.Wire.Node, snapshot.Node) {
		return AppliedSnapshot{}, ErrRestartRequired
	}
	if err := syncer.commit(applied); err != nil {
		return AppliedSnapshot{}, err
	}
	return cloneApplied(applied), nil
}

func (syncer *Synchronizer) LoadCachedSnapshot(expectedNodeID string) (AppliedSnapshot, error) {
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
	if err := writeCredentials(syncer.credentialPath, applied.Users); err != nil {
		return fmt.Errorf("persist Flysky SS2022 credentials: %w", err)
	}
	if syncer.reloader != nil {
		if err := syncer.reloader.LoadFromFile(); err != nil {
			return fmt.Errorf("activate Flysky SS2022 credentials: %w", err)
		}
	}
	syncer.runtime.ReplaceUsers(applied.Wire.ValidUntil, applied.Users)
	if err := flyskyapi.SaveSnapshot(syncer.snapshotPath, applied.Wire); err != nil {
		return fmt.Errorf("persist Flysky snapshot: %w", err)
	}
	if err := flyskyapi.SaveSyncState(syncer.syncStatePath, flyskyapi.SyncState{
		NodeID: applied.Wire.Node.NodeID, SchemaVersion: applied.Wire.SchemaVersion,
		ConfigVersion: applied.Wire.ConfigVersion, Cursor: applied.Wire.Cursor,
		SnapshotValidUntil: applied.Wire.ValidUntil, UpdatedAt: syncer.now().UTC(),
	}); err != nil {
		return fmt.Errorf("persist Flysky synchronization state: %w", err)
	}
	next := cloneApplied(applied)
	syncer.current = &next
	return nil
}

func validateSnapshot(snapshot flyskyapi.Snapshot, expectedNodeID string, now time.Time) (AppliedSnapshot, error) {
	if snapshot.SchemaVersion != 1 {
		return AppliedSnapshot{}, fmt.Errorf("unsupported Flysky snapshot schema version %d", snapshot.SchemaVersion)
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

	users := make([]User, 0, len(snapshot.Users))
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
		fingerprint := base64.RawStdEncoding.EncodeToString(key)
		if other, exists := seenKeys[fingerprint]; exists {
			return AppliedSnapshot{}, fmt.Errorf("Flysky snapshot reuses one SS2022 key for users %s and %s", other, wireUser.UserID)
		}
		seenKeys[fingerprint] = wireUser.UserID
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
	return AppliedSnapshot{Wire: cloneSnapshot(snapshot), ServerKey: serverKey, Users: users}, nil
}

func applyChanges(current flyskyapi.Snapshot, set flyskyapi.Changes, now time.Time) (flyskyapi.Snapshot, bool, error) {
	if strings.TrimSpace(set.NextCursor) == "" {
		return flyskyapi.Snapshot{}, false, errors.New("Flysky changes response is missing next cursor")
	}
	if len(set.Changes) == 0 && set.NextCursor == current.Cursor {
		return current, false, nil
	}
	next := cloneSnapshot(current)
	users := make(map[string]flyskyapi.SnapshotUser, len(next.Users))
	for _, user := range next.Users {
		users[user.UserID] = user
	}
	var previousSequence int64
	for index, change := range set.Changes {
		if change.Sequence < 1 || index > 0 && change.Sequence <= previousSequence || change.ResourceVersion < 1 || !validUUID(change.ResourceID) {
			return flyskyapi.Snapshot{}, false, errors.New("Flysky changes response is unordered or invalid")
		}
		previousSequence = change.Sequence
		switch change.Operation {
		case "upsert_user":
			var user flyskyapi.SnapshotUser
			if err := decodeStrictJSON(change.Payload, &user); err != nil {
				return flyskyapi.Snapshot{}, false, fmt.Errorf("decode Flysky upsert_user payload: %w", err)
			}
			if user.UserID != change.ResourceID {
				return flyskyapi.Snapshot{}, false, errors.New("Flysky upsert_user resource identity does not match its payload")
			}
			users[user.UserID] = user
		case "revoke_user":
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
		case "update_node", "rotate_secret":
			return flyskyapi.Snapshot{}, false, ErrRestartRequired
		default:
			return flyskyapi.Snapshot{}, false, fmt.Errorf("unsupported Flysky node change operation %q", change.Operation)
		}
	}
	next.Users = make([]flyskyapi.SnapshotUser, 0, len(users))
	for _, user := range users {
		next.Users = append(next.Users, user)
	}
	sort.Slice(next.Users, func(i, j int) bool { return next.Users[i].UserID < next.Users[j].UserID })
	next.Cursor = set.NextCursor
	next.GeneratedAt = now.UTC()
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
