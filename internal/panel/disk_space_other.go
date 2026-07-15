//go:build !linux

package panel

import "errors"

type diskSpace struct {
	FreeBytes  uint64
	TotalBytes uint64
}

func readDiskSpace(string) (diskSpace, error) {
	return diskSpace{}, errors.New("disk space metrics are unavailable on this platform")
}
