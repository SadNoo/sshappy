//go:build linux

package panel

import "golang.org/x/sys/unix"

type diskSpace struct {
	FreeBytes  uint64
	TotalBytes uint64
}

func readDiskSpace(path string) (diskSpace, error) {
	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return diskSpace{}, err
	}
	blockSize := uint64(stats.Bsize)
	return diskSpace{
		FreeBytes:  stats.Bavail * blockSize,
		TotalBytes: stats.Blocks * blockSize,
	}, nil
}
