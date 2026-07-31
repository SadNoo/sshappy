package cred

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/ss2022"
	"go.uber.org/zap/zaptest"
)

const testPSKLength = 32

func newTestManagedServer(t *testing.T, initial map[string][]byte) (*ManagedServer, *ss2022.CredStore, *ss2022.CredStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	content, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	tcpStore := new(ss2022.CredStore)
	udpStore := new(ss2022.CredStore)
	manager := NewManager(zaptest.NewLogger(t))
	server, err := manager.RegisterServer("test", path, testPSKLength, tcpStore, udpStore)
	if err != nil {
		t.Fatal(err)
	}
	return server, tcpStore, udpStore, path
}

func TestManagedServerCredentialIsolationAndDuplicatePSK(t *testing.T) {
	server, tcpStore, udpStore, _ := newTestManagedServer(t, map[string][]byte{})
	key := bytes.Repeat([]byte{1}, testPSKLength)
	if err := server.AddCredential("alice", key); err != nil {
		t.Fatal(err)
	}

	key[0] = 9
	credential, ok := server.GetCredential("alice")
	if !ok {
		t.Fatal("alice was not found")
	}
	if credential.UPSK[0] != 1 {
		t.Fatal("mutating AddCredential input changed the stored credential")
	}
	credential.UPSK[0] = 8
	credentials := server.Credentials()
	if len(credentials) != 1 || credentials[0].UPSK[0] != 1 {
		t.Fatal("mutating GetCredential output changed the stored credential")
	}

	hash := ss2022.PSKHash(credentials[0].UPSK)
	if _, ok = tcpStore.LookupUser(hash); !ok {
		t.Fatal("TCP credential store did not receive alice")
	}
	if _, ok = udpStore.LookupUser(hash); !ok {
		t.Fatal("UDP credential store did not receive alice")
	}
	if err := server.AddCredential("bob", credentials[0].UPSK); err == nil {
		t.Fatal("duplicate uPSK was accepted")
	}
	bobKey := bytes.Repeat([]byte{2}, testPSKLength)
	if err := server.AddCredential("bob", bobKey); err != nil {
		t.Fatal(err)
	}
	if err := server.UpdateCredential("bob", credentials[0].UPSK); err == nil {
		t.Fatal("UpdateCredential accepted another user's uPSK")
	}
}

func TestManagedServerLoadRejectsDuplicatePSK(t *testing.T) {
	key := bytes.Repeat([]byte{1}, testPSKLength)
	path := filepath.Join(t.TempDir(), "credentials.json")
	content, err := json.Marshal(map[string][]byte{"alice": key, "bob": key})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(zaptest.NewLogger(t))
	if _, err = manager.RegisterServer("test", path, testPSKLength, new(ss2022.CredStore), nil); err == nil {
		t.Fatal("credential file with duplicate uPSKs was accepted")
	}
}

func TestManagedServerLoadSecuresCredentialFilePermissions(t *testing.T) {
	if !credentialModeEnforced {
		t.Skip("platform confidentiality is not controlled by POSIX mode bits")
	}
	_, _, _, path := newTestManagedServer(t, map[string][]byte{})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("credential file mode after load = %o, want 600", got)
	}
}

func TestManagedServerLoadPreservesPrivateReadOnlyCredentialFile(t *testing.T) {
	if !credentialModeEnforced {
		t.Skip("platform confidentiality is not controlled by POSIX mode bits")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(zaptest.NewLogger(t))
	if _, err := manager.RegisterServer("test", path, testPSKLength, new(ss2022.CredStore), nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0400 {
		t.Fatalf("read-only credential file mode after load = %o, want 400", got)
	}
}

func TestManagedServerRejectsCredentialSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "credentials-target.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}

	manager := NewManager(zaptest.NewLogger(t))
	_, err := manager.RegisterServer("test", path, testPSKLength, new(ss2022.CredStore), nil)
	if !errors.Is(err, ErrCredentialPathSymlink) {
		t.Fatalf("RegisterServer symlink error = %v, want %v", err, ErrCredentialPathSymlink)
	}
}

func TestManagedServerFinalSaveIsAtomicAndPrivate(t *testing.T) {
	server, _, _, path := newTestManagedServer(t, map[string][]byte{})
	ctx, cancel := context.WithCancel(t.Context())
	server.Start(ctx)

	key := bytes.Repeat([]byte{2}, testPSKLength)
	if err := server.AddCredential("alice", key); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := server.Stop(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("credential file mode = %o, want 600", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string][]byte
	if err = json.Unmarshal(content, &saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved["alice"], key) {
		t.Fatal("shutdown did not persist the latest credential")
	}
	if err = server.UpdateCredential("alice", bytes.Repeat([]byte{3}, testPSKLength)); !errors.Is(err, ErrServerStopped) {
		t.Fatalf("UpdateCredential after shutdown = %v, want %v", err, ErrServerStopped)
	}
}

func TestManagedServerConcurrentReloadAndUpdateStayConsistent(t *testing.T) {
	initialKey := bytes.Repeat([]byte{1}, testPSKLength)
	server, tcpStore, udpStore, _ := newTestManagedServer(t, map[string][]byte{"alice": initialKey})
	keys := [][]byte{
		initialKey,
		bytes.Repeat([]byte{2}, testPSKLength),
		bytes.Repeat([]byte{3}, testPSKLength),
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 200 {
			_ = server.UpdateCredential("alice", keys[1+i%2])
		}
	})
	wg.Go(func() {
		for range 200 {
			if err := server.LoadFromFile(); err != nil {
				t.Errorf("LoadFromFile failed: %v", err)
				return
			}
		}
	})
	wg.Wait()

	credential, ok := server.GetCredential("alice")
	if !ok {
		t.Fatal("alice was not found")
	}
	currentHash := ss2022.PSKHash(credential.UPSK)
	for name, store := range map[string]*ss2022.CredStore{"TCP": tcpStore, "UDP": udpStore} {
		matched := 0
		for _, key := range keys {
			_, exists := store.LookupUser(ss2022.PSKHash(key))
			if exists {
				matched++
			}
		}
		if matched != 1 {
			t.Errorf("%s store contains %d candidate credentials, want 1", name, matched)
		}
		if _, exists := store.LookupUser(currentHash); !exists {
			t.Errorf("%s store does not match the managed credential", name)
		}
	}
}
