//go:build !unix

package cred

const credentialModeEnforced = false

// secureCredentialFileMode intentionally does not claim that chmod-style mode
// bits secure a credential file on non-Unix platforms. In particular, Windows
// confidentiality depends on the file and parent directory DACL. Deployments
// must provision that ACL outside this package.
func secureCredentialFileMode(string) error {
	return nil
}
