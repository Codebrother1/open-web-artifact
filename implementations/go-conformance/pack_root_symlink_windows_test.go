//go:build windows

package owa

import "testing"

// The pack-root / ancestor-symlink characterization (issue #42) lives in
// pack_root_symlink_unix_test.go and is compiled only on Unix-like platforms:
// its child-process harness relies on POSIX wait status, and the repository has
// no Windows Go lane. Windows symbolic links, junctions and other reparse points
// are therefore NOT characterized for this implementation and are not equated
// with the tested POSIX symlinks. This explicit skip records that absence.
func TestPackRootSymlinkCharacterizationUnixOnly(t *testing.T) {
	t.Skip("pack-root/ancestor symlink characterization is compiled only on Unix-like platforms; see pack_root_symlink_unix_test.go (Linux/macOS)")
}
