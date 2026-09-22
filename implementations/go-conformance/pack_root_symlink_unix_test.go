//go:build unix

package owa

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Pack-root and ancestor symbolic links (issue #42) — a CHARACTERIZATION of
// current behaviour, not a normative rule.
//
// spec-v0.2.md "Entry types" (issue #40) governs entries discovered BENEATH the
// directory being packed: a symbolic link found there fails OWA_SYMLINK. It says
// nothing about the pack root itself or about links in ancestor components of
// the supplied path, and this implementation resolves the root with
// filepath.Abs and never inspects it with os.Lstat. This file records what that
// means today, so the compatibility boundary is executable evidence:
//
//   - a directory symlink supplied AS the root (relative or absolute target), or
//     a link in an ANCESTOR component with an ordinary directory as the final
//     component, is followed and packs to the same identity as the direct path,
//     with no host path spelling in the artifact paths;
//   - through every such root spelling, a link found INSIDE the tree still fails
//     OWA_SYMLINK — following the supplied path is distinct from following
//     discovered entries;
//   - a dangling root link, or a root link to a regular file, fails with the
//     host *fs.PathError (no artifact, no portable OWA category); the errno is
//     asserted because POSIX fixes it (ENOENT, ENOTDIR) on the platforms this
//     file compiles for.
//
// The policy for root and ancestor links remains UNRESOLVED; these tests prove
// neither confinement (nothing stops a root alias from denoting any directory
// the caller may read) nor race resistance. Every pack that involves a symbolic
// link runs in a CHILD PROCESS under the external deadline of packInChild
// (pack_nonregular_unix_test.go), which kills and reaps a blocked child. This
// file is compiled only on Unix-like platforms (the harness relies on POSIX wait
// status; no Windows Go lane exists); it is standard library only and involves
// no Node or JavaScript.

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err) // on a supported platform this is a failure, never a skip
	}
}

type rootSpelling struct{ label, root string }

// rootFixture materializes the anchor at base/parent/site and spells that
// directory four ways:
//
//	direct    base/parent/site                     (no link anywhere in the spelling)
//	relative  base/rel -> parent/site              (relative-target link AS the root)
//	absolute  base/abs -> <absolute>/parent/site   (absolute-target link AS the root)
//	ancestor  base/anc/site, base/anc -> parent    (link in an ANCESTOR component; site is an ordinary directory)
//
// os.MkdirAll creates only ordinary directories, so no spelling contains a link
// the test did not create; whether the temporary directory itself lies beneath
// a host-level link (macOS: /var -> /private/var) is reported, not assumed.
type rootFixture struct {
	base, site string
	spellings  []rootSpelling
	hostNames  []string // every name the host spelling could leak into an artifact path
}

func newRootFixture(t *testing.T, files []setupFile) rootFixture {
	t.Helper()
	base := shortTemp(t)
	site := filepath.Join(base, "parent", "site")
	materialize(t, site, files)
	mustSymlink(t, filepath.Join("parent", "site"), filepath.Join(base, "rel"))
	mustSymlink(t, site, filepath.Join(base, "abs"))
	mustSymlink(t, "parent", filepath.Join(base, "anc"))
	real, err := filepath.EvalSymlinks(site)
	if err != nil {
		t.Fatal(err)
	}
	if real == site {
		t.Logf("direct root has no symlinked ancestor on this host")
	} else {
		t.Logf("direct root already has a host-level symlinked ancestor on this host: %s resolves to %s", site, real)
	}
	return rootFixture{
		base: base, site: site,
		spellings: []rootSpelling{
			{"direct path", site},
			{"relative-target root link", filepath.Join(base, "rel")},
			{"absolute-target root link", filepath.Join(base, "abs")},
			{"ancestor link + ordinary final directory", filepath.Join(base, "anc", "site")},
		},
		hostNames: []string{filepath.Base(base), "parent", "site", "rel", "abs", "anc"},
	}
}

// assertNoHostSpelling: no component of the host spelling — temporary directory,
// link or directory names — appears in any artifact path.
func assertNoHostSpelling(t *testing.T, s packSnapshot, hostNames []string) {
	t.Helper()
	for _, p := range s.paths {
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("%s is not a complete artifact path", p)
		}
		for _, seg := range strings.Split(p, "/")[1:] {
			for _, name := range hostNames {
				if seg == name {
					t.Fatalf("host name %s leaked into artifact path %s", name, p)
				}
			}
		}
		if strings.Contains(p, os.TempDir()) {
			t.Fatalf("temporary directory leaked into %s", p)
		}
	}
}

// failedWithHostError: the failure is a HOST filesystem error — no artifact, no
// portable OWA category, a *fs.PathError carrying the expected POSIX errno. The
// message is logged, never matched.
func failedWithHostError(t *testing.T, res childPack, label string, want syscall.Errno) childPack {
	t.Helper()
	if res.OK {
		t.Fatalf("%s: packing unexpectedly produced an artifact %s", label, res.Digest)
	}
	if res.Known || res.Category != "" {
		t.Fatalf("%s: expected a host filesystem error, got portable category %q", label, res.Category)
	}
	if res.HostOp == "" || res.HostErrno == 0 {
		t.Fatalf("%s: expected a *fs.PathError carrying an errno, got %q", label, res.Message)
	}
	got := syscall.Errno(res.HostErrno)
	t.Logf("%s: host error op=%s errno=%d (%v) message=%q", label, res.HostOp, res.HostErrno, got, res.Message)
	if got != want {
		t.Fatalf("%s: expected %v, got %v", label, want, got)
	}
	return res
}

func TestPackRootAliasesPackIdentically(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	fx := newRootFixture(t, files)
	// The direct path contains no link the test created and its tree has none, so
	// it is packed in-process as the reference — and once more in a child, which
	// proves the child's structured result is the complete identity.
	packed, err := PackDirectory(fx.site, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	direct := snapshotOf(t, packed)
	assertMatchesAnchor(t, direct, expected, files)
	assertNoHostSpelling(t, direct, fx.hostNames)
	assertSameSnapshot(t, direct, packedInChild(t, packInChild(t, fx.site, entrypoint)))
	for _, sp := range fx.spellings[1:] {
		t.Run(sp.label, func(t *testing.T) {
			viaLink := packedInChild(t, packInChild(t, sp.root, entrypoint))
			assertSameSnapshot(t, direct, viaLink) // canonical bytes, digest, order, blob digests, blob bytes
			assertMatchesAnchor(t, viaLink, expected, files)
			assertNoHostSpelling(t, viaLink, fx.hostNames)
		})
	}
}

func TestPackRootAliasesStillRejectSymlinksInsideTree(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	fx := newRootFixture(t, files)
	outside := shortTemp(t)
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	targets := []struct{ label, target string }{
		{"regular-file target", filepath.Join(fx.site, "index.html")},
		{"dangling target", filepath.Join(fx.site, "does-not-exist")},
		{"directory target", filepath.Join(fx.site, "assets")},
		{"external regular-file target", filepath.Join(outside, "secret.txt")},
	}
	for _, sp := range fx.spellings {
		for _, tc := range targets {
			t.Run(sp.label+"/"+tc.label, func(t *testing.T) {
				// The link is created in the real directory; every spelling sees it.
				link := filepath.Join(fx.site, "link-under-test")
				mustSymlink(t, tc.target, link)
				t.Cleanup(func() { os.Remove(link) })
				failedInChild(t, packInChild(t, sp.root, entrypoint), CatSymlink)
			})
		}
		// Every link removed: this spelling packs to the anchor again.
		assertMatchesAnchor(t, packedInChild(t, packInChild(t, sp.root, entrypoint)), expected, files)
	}
}

func TestPackDanglingRootLinkFailsWithHostError(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	base := shortTemp(t)
	site := filepath.Join(base, "parent", "site")
	materialize(t, site, files)
	mustSymlink(t, filepath.Join("parent", "nowhere"), filepath.Join(base, "dangling-rel"))
	mustSymlink(t, filepath.Join(base, "parent", "nowhere"), filepath.Join(base, "dangling-abs"))
	rel := failedWithHostError(t, packInChild(t, filepath.Join(base, "dangling-rel"), entrypoint), "dangling root link (relative target)", syscall.ENOENT)
	abs := failedWithHostError(t, packInChild(t, filepath.Join(base, "dangling-abs"), entrypoint), "dangling root link (absolute target)", syscall.ENOENT)
	if rel.HostErrno != abs.HostErrno || rel.HostOp != abs.HostOp {
		t.Fatalf("relative and absolute dangling root links fail differently: %+v vs %+v", rel, abs)
	}
	// The neighbouring real directory is untouched by the failed attempts.
	packed, err := PackDirectory(site, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	assertMatchesAnchor(t, snapshotOf(t, packed), expected, files)
}

func TestPackRootLinkToRegularFileFailsWithHostError(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	base := shortTemp(t)
	site := filepath.Join(base, "parent", "site")
	materialize(t, site, files)
	mustSymlink(t, filepath.Join("parent", "site", "index.html"), filepath.Join(base, "file-rel"))
	mustSymlink(t, filepath.Join(site, "index.html"), filepath.Join(base, "file-abs"))
	rel := failedWithHostError(t, packInChild(t, filepath.Join(base, "file-rel"), entrypoint), "root link to a regular file (relative target)", syscall.ENOTDIR)
	abs := failedWithHostError(t, packInChild(t, filepath.Join(base, "file-abs"), entrypoint), "root link to a regular file (absolute target)", syscall.ENOTDIR)
	// For contrast: the regular file itself, supplied directly as the root, fails the same way — the link adds nothing.
	direct := failedWithHostError(t, packInChild(t, filepath.Join(site, "index.html"), entrypoint), "a regular file supplied directly as the root", syscall.ENOTDIR)
	if rel.HostErrno != abs.HostErrno || abs.HostErrno != direct.HostErrno {
		t.Fatalf("file-target root spellings fail differently: %+v / %+v / %+v", rel, abs, direct)
	}
	packed, err := PackDirectory(site, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	assertMatchesAnchor(t, snapshotOf(t, packed), expected, files)
}
