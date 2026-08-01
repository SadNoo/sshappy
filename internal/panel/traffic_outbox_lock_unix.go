//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package panel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// unixTrafficOutboxProcessLock holds two lifetime locks. The state-directory
// inode is authoritative and cannot be bypassed by unlinking or renaming the
// visible .lock file. The file lock remains as an operator-visible ownership
// marker and provides per-outbox diagnostics.
type unixTrafficOutboxProcessLock struct {
	dirFile  *os.File
	dirInfo  os.FileInfo
	dirPath  string
	lockFile *os.File
	lockInfo os.FileInfo
	lockPath string
}

func acquireTrafficOutboxProcessLock(path string) (trafficOutboxProcessLock, error) {
	dirPath := filepath.Dir(path)
	dirFD, err := unix.Open(dirPath, unix.O_CLOEXEC|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open traffic outbox state directory %q for locking: %w", dirPath, err)
	}
	dirFile := os.NewFile(uintptr(dirFD), dirPath)
	if dirFile == nil {
		_ = unix.Close(dirFD)
		return nil, fmt.Errorf("failed to create traffic outbox state-directory lock handle for %q", dirPath)
	}
	closeDirOnError := func(err error) (trafficOutboxProcessLock, error) {
		_ = dirFile.Close()
		return nil, err
	}
	dirInfo, err := dirFile.Stat()
	if err != nil {
		return closeDirOnError(fmt.Errorf("failed to inspect traffic outbox state directory %q: %w", dirPath, err))
	}
	dirPathInfo, err := os.Lstat(dirPath)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 || dirPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(dirInfo, dirPathInfo) {
		return closeDirOnError(fmt.Errorf("traffic outbox state directory %q must be a stable private directory (0700): %v", dirPath, err))
	}
	if err := unix.Flock(dirFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeDirOnError(fmt.Errorf("traffic outbox state directory %q is already in use by another process", dirPath))
		}
		return closeDirOnError(fmt.Errorf("failed to lock traffic outbox state directory %q: %w", dirPath, err))
	}

	fd, err := unix.Open(path, unix.O_CLOEXEC|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR, 0600)
	if err != nil {
		_ = unix.Flock(dirFD, unix.LOCK_UN)
		return closeDirOnError(fmt.Errorf("failed to open traffic outbox process lock %q: %w", path, err))
	}
	lockFile := os.NewFile(uintptr(fd), path)
	if lockFile == nil {
		_ = unix.Close(fd)
		_ = unix.Flock(dirFD, unix.LOCK_UN)
		return closeDirOnError(fmt.Errorf("failed to create traffic outbox process lock handle for %q", path))
	}
	closeAllOnError := func(err error) (trafficOutboxProcessLock, error) {
		_ = lockFile.Close()
		_ = unix.Flock(dirFD, unix.LOCK_UN)
		_ = dirFile.Close()
		return nil, err
	}
	lockInfo, err := lockFile.Stat()
	if err != nil {
		return closeAllOnError(fmt.Errorf("failed to inspect traffic outbox process lock %q: %w", path, err))
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm()&0077 != 0 {
		return closeAllOnError(fmt.Errorf("traffic outbox process lock %q must be a private regular file (0600)", path))
	}
	if err := validateTrafficOutboxLinkCount(lockInfo, path); err != nil {
		return closeAllOnError(err)
	}
	lockPathInfo, err := os.Lstat(path)
	if err != nil || lockPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockInfo, lockPathInfo) {
		return closeAllOnError(fmt.Errorf("traffic outbox process lock %q was replaced while opening: %v", path, err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeAllOnError(fmt.Errorf("traffic outbox %q is already in use by another process", path[:len(path)-len(".lock")]))
		}
		return closeAllOnError(fmt.Errorf("failed to lock traffic outbox process lock %q: %w", path, err))
	}
	return &unixTrafficOutboxProcessLock{
		dirFile:  dirFile,
		dirInfo:  dirInfo,
		dirPath:  dirPath,
		lockFile: lockFile,
		lockInfo: lockInfo,
		lockPath: path,
	}, nil
}

func openTrafficOutboxFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to create file handle for %q", path)
	}
	return file, nil
}

func validateLockedTrafficOutboxDirectory(file *os.File, expected os.FileInfo, path string) error {
	if file == nil || expected == nil {
		return fmt.Errorf("traffic outbox state-directory lock handle for %q is missing", path)
	}
	handleInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to inspect held traffic outbox state-directory lock %q: %w", path, err)
	}
	pathInfo, pathErr := os.Lstat(path)
	if !os.SameFile(expected, handleInfo) || !handleInfo.IsDir() || handleInfo.Mode().Perm()&0077 != 0 ||
		pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || pathInfo.Mode().Perm()&0077 != 0 || !os.SameFile(handleInfo, pathInfo) {
		return fmt.Errorf("traffic outbox state directory %q is missing, replaced, or unsafe: %v", path, pathErr)
	}
	return nil
}

func validateLockedTrafficOutboxFile(file *os.File, expected os.FileInfo, path string) error {
	if file == nil || expected == nil {
		return fmt.Errorf("traffic outbox lock handle for %q is missing", path)
	}
	handleInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to inspect held traffic outbox lock %q: %w", path, err)
	}
	if !os.SameFile(expected, handleInfo) || !handleInfo.Mode().IsRegular() || handleInfo.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("held traffic outbox lock %q was replaced or became unsafe", path)
	}
	if err := validateTrafficOutboxLinkCount(handleInfo, path); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0077 != 0 || !os.SameFile(handleInfo, pathInfo) {
		return fmt.Errorf("traffic outbox lock path %q is missing, replaced, or unsafe: %v", path, err)
	}
	if err := validateTrafficOutboxLinkCount(pathInfo, path); err != nil {
		return err
	}
	return nil
}

func (l *unixTrafficOutboxProcessLock) Validate() error {
	if l == nil {
		return errors.New("traffic outbox process lock is missing")
	}
	if err := validateLockedTrafficOutboxDirectory(l.dirFile, l.dirInfo, l.dirPath); err != nil {
		return err
	}
	return validateLockedTrafficOutboxFile(l.lockFile, l.lockInfo, l.lockPath)
}

func validateTrafficOutboxLinkCount(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to inspect hard-link count for traffic outbox file %q", path)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("traffic outbox file %q must not have multiple hard links", path)
	}
	return nil
}

func (l *unixTrafficOutboxProcessLock) Close() error {
	if l == nil {
		return nil
	}
	var lockUnlockErr, lockCloseErr, dirUnlockErr, dirCloseErr error
	if l.lockFile != nil {
		lockUnlockErr = unix.Flock(int(l.lockFile.Fd()), unix.LOCK_UN)
		lockCloseErr = l.lockFile.Close()
		l.lockFile = nil
	}
	if l.dirFile != nil {
		dirUnlockErr = unix.Flock(int(l.dirFile.Fd()), unix.LOCK_UN)
		dirCloseErr = l.dirFile.Close()
		l.dirFile = nil
	}
	return errors.Join(lockUnlockErr, lockCloseErr, dirUnlockErr, dirCloseErr)
}
