//go:build unix

package cred

import (
	"fmt"
	"os"
)

const credentialModeEnforced = true

// secureCredentialFileMode removes group and other access from a credential
// file before its contents are loaded. This protects POSIX mode bits; callers
// must still ensure the parent directory and any platform ACLs are trusted.
func secureCredentialFileMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	// Permit an already-private read-only secret, which may live on a
	// read-only mount. Other modes are normalized to owner read/write only.
	if perm := info.Mode().Perm(); perm == 0600 || perm == 0400 {
		return nil
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to restrict credential file permissions: %w", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		return fmt.Errorf("credential file permissions remain %o after chmod", perm)
	}
	return nil
}
