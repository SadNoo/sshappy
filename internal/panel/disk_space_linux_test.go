//go:build linux

package panel

import "testing"

func TestReadDiskSpace(t *testing.T) {
	space, err := readDiskSpace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if space.TotalBytes == 0 || space.FreeBytes == 0 || space.FreeBytes > space.TotalBytes {
		t.Fatalf("invalid disk space metrics: %+v", space)
	}
}
