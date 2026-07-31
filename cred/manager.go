package cred

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap"
)

var (
	ErrEmptyUsername         = errors.New("empty username")
	ErrNonexistentUser       = errors.New("nonexistent user")
	ErrServerStopped         = errors.New("managed credential server is stopped")
	ErrCredentialPathSymlink = errors.New("credential path must not be a symbolic link")
	ErrCredentialPathNotFile = errors.New("credential path must be a regular file")
)

// ManagedServer stores information about a server whose credentials are managed by the credential manager.
type ManagedServer struct {
	pskLength           int
	tcp                 *ss2022.CredStore
	udp                 *ss2022.CredStore
	name                string
	path                string
	cachedContent       string
	cachedCredMap       map[string]*cachedUserCredential
	cachedUserLookupMap ss2022.UserLookupMap
	mu                  sync.RWMutex
	fileMu              sync.Mutex
	wg                  sync.WaitGroup
	saveQueue           chan struct{}
	generation          uint64
	savedGeneration     uint64
	stopping            bool
	finalSaveErr        error
	logger              *zap.Logger
}

// Name returns the name of the server.
func (s *ManagedServer) Name() string {
	return s.name
}

// UserCredential stores a user's credential.
type UserCredential struct {
	Name string `json:"username"`
	UPSK []byte `json:"uPSK"`
}

// Compare is useful for sorting user credentials by username.
func (uc UserCredential) Compare(other UserCredential) int {
	return cmp.Compare(uc.Name, other.Name)
}

type cachedUserCredential struct {
	uPSK     []byte
	uPSKHash [ss2022.IdentityHeaderLength]byte
}

// Credentials returns the server credentials.
func (s *ManagedServer) Credentials() []UserCredential {
	s.mu.RLock()
	ucs := make([]UserCredential, 0, len(s.cachedCredMap))
	for username, cachedCred := range s.cachedCredMap {
		ucs = append(ucs, UserCredential{
			Name: username,
			UPSK: bytes.Clone(cachedCred.uPSK),
		})
	}
	s.mu.RUnlock()
	slices.SortFunc(ucs, UserCredential.Compare)
	return ucs
}

// GetCredential returns the user credential.
func (s *ManagedServer) GetCredential(username string) (UserCredential, bool) {
	s.mu.RLock()
	cachedCred := s.cachedCredMap[username]
	if cachedCred == nil {
		s.mu.RUnlock()
		return UserCredential{}, false
	}
	uc := UserCredential{
		Name: username,
		UPSK: bytes.Clone(cachedCred.uPSK),
	}
	s.mu.RUnlock()
	return uc, true
}

func (s *ManagedServer) saveToFile() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()

	s.mu.RLock()
	if s.savedGeneration == s.generation {
		s.mu.RUnlock()
		return nil
	}
	generation := s.generation
	uPSKMap := make(map[string][]byte, len(s.cachedCredMap))
	for username, uc := range s.cachedCredMap {
		uPSKMap[username] = bytes.Clone(uc.uPSK)
	}
	s.mu.RUnlock()

	b, err := json.MarshalIndent(uPSKMap, "", "    ")
	if err != nil {
		return err
	}
	b = append(b, '\n') // b has plenty of unused capacity.

	if err = writeFileAtomic(s.path, b); err != nil {
		return err
	}

	s.mu.Lock()
	s.cachedContent = string(b)
	s.savedGeneration = generation
	s.mu.Unlock()
	return nil
}

func writeFileAtomic(path string, content []byte) (err error) {
	if err = rejectCredentialSymlink(path, true); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()

	if err = temp.Chmod(0600); err != nil {
		return err
	}
	if _, err = temp.Write(content); err != nil {
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
	if runtime.GOOS == "windows" {
		return nil
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func rejectCredentialSymlink(path string, allowNotExist bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if allowNotExist && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrCredentialPathSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrCredentialPathNotFile, path)
	}
	return nil
}

func secureCredentialFile(path string) error {
	// The parent directory must not be writable by an untrusted user. Recheck
	// after adjusting permissions to catch ordinary symlink replacement; this
	// path validation is not a substitute for trusted directory ownership.
	if err := rejectCredentialSymlink(path, false); err != nil {
		return err
	}
	if err := secureCredentialFileMode(path); err != nil {
		return err
	}
	return rejectCredentialSymlink(path, false)
}

func (s *ManagedServer) dequeueSave(ctx context.Context) {
	for {
		// Wait for incoming save job.
		select {
		case <-s.saveQueue:
		case <-ctx.Done():
			s.finishSaving()
			return
		}

		// Wait for cooldown.
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			s.finishSaving()
			return
		}

		// Clear save queue after cooldown.
		select {
		case <-s.saveQueue:
		default:
		}

		if err := s.saveToFile(); err != nil {
			s.logger.Error("Failed to save credentials", zap.Error(err))
			// Keep retrying while the service is running. The queue is bounded,
			// so repeated failures cannot create unbounded work.
			s.enqueueSave()
		}
	}
}

func (s *ManagedServer) finishSaving() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()

	err := s.saveToFile()
	if err != nil {
		s.logger.Error("Failed to save credentials during shutdown", zap.Error(err))
	}
	s.mu.Lock()
	s.finalSaveErr = err
	s.mu.Unlock()
}

// Start starts the managed server.
func (s *ManagedServer) Start(ctx context.Context) {
	s.wg.Go(func() {
		s.dequeueSave(ctx)
	})
}

// Stop stops the managed server.
func (s *ManagedServer) Stop() error {
	s.wg.Wait()
	s.mu.RLock()
	err := s.finalSaveErr
	s.mu.RUnlock()
	return err
}

func (s *ManagedServer) enqueueSave() {
	select {
	case s.saveQueue <- struct{}{}:
	default:
	}
}

func (s *ManagedServer) replaceProdULMLocked() {
	if s.tcp != nil {
		s.tcp.ReplaceUserLookupMap(maps.Clone(s.cachedUserLookupMap))
	}
	if s.udp != nil {
		s.udp.ReplaceUserLookupMap(maps.Clone(s.cachedUserLookupMap))
	}
}

// AddCredential adds a user credential.
func (s *ManagedServer) AddCredential(username string, uPSK []byte) error {
	if username == "" {
		return ErrEmptyUsername
	}
	if len(uPSK) != s.pskLength {
		return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
	}
	uPSK = bytes.Clone(uPSK)
	uPSKHash := ss2022.PSKHash(uPSK)
	c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ErrServerStopped
	}
	if s.cachedCredMap[username] != nil {
		s.mu.Unlock()
		return fmt.Errorf("user %s already exists", username)
	}
	if existing, ok := s.cachedUserLookupMap[uPSKHash]; ok {
		s.mu.Unlock()
		return fmt.Errorf("duplicate uPSK for user %s and %s", existing.Name, username)
	}
	uc := &cachedUserCredential{
		uPSK:     uPSK,
		uPSKHash: uPSKHash,
	}
	s.cachedCredMap[username] = uc
	s.cachedUserLookupMap[uc.uPSKHash] = c
	s.generation++
	s.replaceProdULMLocked()
	s.mu.Unlock()
	s.enqueueSave()
	return nil
}

// UpdateCredential updates a user credential.
func (s *ManagedServer) UpdateCredential(username string, uPSK []byte) error {
	if len(uPSK) != s.pskLength {
		return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
	}
	uPSK = bytes.Clone(uPSK)
	newUPSKHash := ss2022.PSKHash(uPSK)
	c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ErrServerStopped
	}
	uc := s.cachedCredMap[username]
	if uc == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNonexistentUser, username)
	}
	if bytes.Equal(uc.uPSK, uPSK) {
		s.mu.Unlock()
		return fmt.Errorf("user %s already has the same uPSK", username)
	}
	if existing, ok := s.cachedUserLookupMap[newUPSKHash]; ok && existing.Name != username {
		s.mu.Unlock()
		return fmt.Errorf("duplicate uPSK for user %s and %s", existing.Name, username)
	}
	oldUPSKHash := uc.uPSKHash
	uc.uPSK = uPSK
	uc.uPSKHash = newUPSKHash
	delete(s.cachedUserLookupMap, oldUPSKHash)
	s.cachedUserLookupMap[newUPSKHash] = c
	s.generation++
	s.replaceProdULMLocked()
	s.mu.Unlock()
	s.enqueueSave()
	return nil
}

// DeleteCredential deletes a user credential.
func (s *ManagedServer) DeleteCredential(username string) error {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ErrServerStopped
	}
	uc := s.cachedCredMap[username]
	if uc == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNonexistentUser, username)
	}
	delete(s.cachedCredMap, username)
	delete(s.cachedUserLookupMap, uc.uPSKHash)
	s.generation++
	s.replaceProdULMLocked()
	s.mu.Unlock()
	s.enqueueSave()
	return nil
}

// LoadFromFile loads credentials from the configured credential file
// and applies the changes to the associated credential stores.
func (s *ManagedServer) LoadFromFile() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()

	if err := secureCredentialFile(s.path); err != nil {
		return err
	}
	content, close, err := mmap.ReadFile[string](s.path)
	if err != nil {
		return err
	}
	defer close()

	// Skip if the file content is unchanged.
	s.mu.RLock()
	if content == s.cachedContent {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	r := strings.NewReader(content)
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	var uPSKMap map[string][]byte
	if err = d.Decode(&uPSKMap); err != nil {
		return err
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("credential file contains trailing JSON data")
	}
	if uPSKMap == nil {
		uPSKMap = make(map[string][]byte)
	}

	userLookupMap := make(ss2022.UserLookupMap, len(uPSKMap))
	credMap := make(map[string]*cachedUserCredential, len(uPSKMap))
	for username, uPSK := range uPSKMap {
		if username == "" {
			return ErrEmptyUsername
		}
		if len(uPSK) != s.pskLength {
			return &ss2022.PSKLengthError{PSK: uPSK, ExpectedLength: s.pskLength}
		}
		uPSK = bytes.Clone(uPSK)

		uPSKHash := ss2022.PSKHash(uPSK)
		c, ok := userLookupMap[uPSKHash]
		if ok {
			return fmt.Errorf("duplicate uPSK for user %s and %s", c.Name, username)
		}
		c, err := ss2022.NewServerUserCipherConfig(username, uPSK, s.udp != nil)
		if err != nil {
			return err
		}

		userLookupMap[uPSKHash] = c
		credMap[username] = &cachedUserCredential{uPSK, uPSKHash}
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ErrServerStopped
	}
	s.generation++
	s.savedGeneration = s.generation
	s.cachedContent = strings.Clone(content)
	s.cachedUserLookupMap = userLookupMap
	s.cachedCredMap = credMap
	s.replaceProdULMLocked()
	s.mu.Unlock()

	return nil
}

// Manager manages credentials for servers of supported protocols.
type Manager struct {
	logger  *zap.Logger
	servers map[string]*ManagedServer
}

// NewManager returns a new credential manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		logger:  logger,
		servers: make(map[string]*ManagedServer),
	}
}

// Servers returns the number of managed servers and an iterator over them.
func (m *Manager) Servers() (int, iter.Seq[*ManagedServer]) {
	return len(m.servers), maps.Values(m.servers)
}

// ReloadAll asks all managed servers to reload credentials from files.
func (m *Manager) ReloadAll() {
	for name, s := range m.servers {
		if err := s.LoadFromFile(); err != nil {
			m.logger.Error("Failed to reload credentials", zap.String("server", name), zap.Error(err))
			continue
		}
		m.logger.Info("Reloaded credentials", zap.String("server", name))
	}
}

// LoadAll loads credentials for all managed servers.
func (m *Manager) LoadAll() error {
	for name, s := range m.servers {
		if err := s.LoadFromFile(); err != nil {
			return fmt.Errorf("failed to load credentials for server %s: %w", name, err)
		}
		m.logger.Debug("Loaded credentials", zap.String("server", name))
	}
	return nil
}

var _ shadowsocks.Service = (*Manager)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (*Manager) ZapField() zap.Field {
	return zap.String("service", "credential manager")
}

// Start starts all managed servers and registers to reload on SIGUSR1.
//
// Start implements [shadowsocks.Service.Start].
func (m *Manager) Start(ctx context.Context) error {
	for _, s := range m.servers {
		s.Start(ctx)
	}
	return nil
}

// Stop gracefully stops all managed servers.
//
// Stop implements [shadowsocks.Service.Stop].
func (m *Manager) Stop() error {
	var errs []error
	for name, s := range m.servers {
		if err := s.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to save credentials for server %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// RegisterServer registers a server to the manager.
func (m *Manager) RegisterServer(name, path string, pskLength int, tcpCredStore, udpCredStore *ss2022.CredStore) (*ManagedServer, error) {
	s := m.servers[name]
	if s != nil {
		return nil, fmt.Errorf("server already registered: %s", name)
	}
	s = &ManagedServer{
		pskLength: pskLength,
		tcp:       tcpCredStore,
		udp:       udpCredStore,
		name:      name,
		path:      path,
		saveQueue: make(chan struct{}, 1),
		logger:    m.logger,
	}
	if err := s.LoadFromFile(); err != nil {
		return nil, fmt.Errorf("failed to load credentials for server %s: %w", name, err)
	}
	m.servers[name] = s
	m.logger.Debug("Registered server for credential management", zap.String("server", name))
	return s, nil
}
