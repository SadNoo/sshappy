// Package mysqlmigration exposes the release migration to the runtime so a
// fresh installation does not depend on a shell or mysql client in the image.
package mysqlmigration

import _ "embed"

// version1 is the exact SQL file shipped in release archives and images.
//
//go:embed 0001_traffic_batch.sql
var version1 string

// Version1 returns the immutable embedded migration text.
func Version1() string {
	return version1
}
