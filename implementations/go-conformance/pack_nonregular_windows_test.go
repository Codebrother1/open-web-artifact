//go:build windows

package owa

import "testing"

// The real FIFO / Unix-domain-socket tests for non-regular directory entries
// (issue #40) live in pack_nonregular_unix_test.go and are compiled only on
// Unix-like platforms, where such entries can be created without privileges.
// Windows has no equivalent unprivileged special file; the entry-type rule is
// still exercised there through the corpus (symlink rejection, regular files)
// and the platform-independent pack tests. This explicit skip records that
// only the POSIX-specific cases are absent on Windows.
func TestPackNonRegularEntriesPOSIXOnly(t *testing.T) {
	t.Skip("FIFOs and Unix-domain socket files are POSIX-specific; see pack_nonregular_unix_test.go (Linux/macOS)")
}
