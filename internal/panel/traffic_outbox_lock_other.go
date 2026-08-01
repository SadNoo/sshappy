//go:build windows || plan9 || js || wasip1

package panel

import (
	"fmt"
	"os"
	"runtime"
)

func acquireTrafficOutboxProcessLock(path string) (trafficOutboxProcessLock, error) {
	return nil, fmt.Errorf("traffic outbox process locking is not supported on %s; sshappy 4.4 refuses to run without a single-writer lock for %q", runtime.GOOS, path)
}

func openTrafficOutboxFileNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

type unsupportedTrafficOutboxProcessLock struct{}

func (*unsupportedTrafficOutboxProcessLock) Validate() error {
	return fmt.Errorf("traffic outbox process locking is not supported on %s", runtime.GOOS)
}

func (*unsupportedTrafficOutboxProcessLock) Close() error { return nil }

func validateTrafficOutboxLinkCount(os.FileInfo, string) error {
	return nil
}
