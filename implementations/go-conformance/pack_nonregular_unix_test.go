//go:build unix

package owa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Non-regular directory entries (issue #40; spec-v0.2.md "Directory packing" →
// "Entry types"). Entries are classified without following links: symbolic
// links fail OWA_SYMLINK, directories recurse, regular files pack, everything
// else (FIFO, socket, device, …) is skipped without being opened, read or
// connected to, and without changing the identity of the regular files. The
// portable corpus cannot materialize such entries uniformly, so this rule is
// pinned here with REAL entries created without privileges — a FIFO
// (syscall.Mkfifo) and a bound Unix-domain socket (net.Listen) in a short
// temporary directory. Device nodes are not exercised (privileged); they share
// the "neither directory nor regular file" branch of walk(). This file is
// compiled only on Unix-like platforms; a setup failure here is a FAILURE.
// No Node or JavaScript is involved; only the standard library is used.
//
// Two harness rules hold throughout this file:
//
//  1. PROCESS ISOLATION. A FIFO with no writer blocks any open for reading
//     indefinitely, and a blocked read cannot be cancelled in-process. So
//     EVERY pack operation that could meet a FIFO — directly, or through a
//     symbolic link should the link rule ever regress to following links —
//     runs in a CHILD PROCESS under an external deadline (packInChild): the
//     test binary re-executes itself running only TestHelperProcessPackNonRegular,
//     which prints ONE JSON document (the complete packed identity, or the
//     error category) and exits; the parent asserts on it. On deadline
//     exec.CommandContext kills the child with SIGKILL, Wait reaps it, the
//     test checks the pid is gone and fails. Only trees made of nothing but
//     regular files and directories are ever packed in-process, and each such
//     call is the reference the child's structured result is compared with.
//
//  2. CLEANUP AT CREATION TIME. A listener's cleanup is registered with
//     t.Cleanup the moment the bind succeeds — before anything else can fail —
//     so it runs whether the test passes, fails, or fails because a child had
//     to be killed; a later bind failure (t.Fatalf) still closes every
//     listener bound before it.

// anchorVector loads pack-cross-language-anchor: the regular-file baseline is
// checked against the UNCHANGED static corpus expectations, not against this
// implementation's own output.
func anchorVector(t *testing.T) (files []setupFile, entrypoint string, expected expectedFields) {
	t.Helper()
	c := loadCorpus(t, "pack.json")
	for _, vec := range c.Vectors {
		if vec.ID != "pack-cross-language-anchor" {
			continue
		}
		var input struct {
			Files      []setupFile `json:"files"`
			Entrypoint string      `json:"entrypoint"`
		}
		if err := json.Unmarshal(vec.Input, &input); err != nil {
			t.Fatal(err)
		}
		return input.Files, input.Entrypoint, decodeExpected(t, vec.Expected)
	}
	t.Fatal("pack-cross-language-anchor missing from the corpus")
	return nil, "", expectedFields{}
}

// anchorPaths returns the anchor manifest's file paths in their static order.
func anchorPaths(t *testing.T, expected expectedFields) []string {
	t.Helper()
	var manifest struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	if err := json.Unmarshal(expected.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range manifest.Files {
		paths = append(paths, f.Path)
	}
	return paths
}

// shortTemp keeps Unix socket paths well under the ~104-byte limit.
func shortTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "o-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo %s: %v", path, err)
	}
}

// boundSocket is a Unix-domain socket bound at path that counts connection
// attempts. close() stops accepting and unlinks the socket file; it is
// registered with t.Cleanup immediately after a successful bind, so it runs on
// every exit path — including a later bind failing with t.Fatalf.
type boundSocket struct {
	path  string
	ln    net.Listener
	conns int32
	done  chan struct{}
}

func bindSocket(t *testing.T, path string) *boundSocket {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("bind socket %s: %v", path, err) // listeners bound earlier are closed by their own t.Cleanup
	}
	s := &boundSocket{path: path, ln: ln, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&s.conns, 1)
			c.Close()
		}
	}()
	t.Cleanup(s.close)
	return s
}

func (s *boundSocket) close() {
	s.ln.Close() // unlinks the socket file; idempotent
	<-s.done
}

func assertNoConnections(t *testing.T, sockets ...*boundSocket) {
	t.Helper()
	for _, s := range sockets {
		if n := atomic.LoadInt32(&s.conns); n != 0 {
			t.Fatalf("the packer connected to %s %d time(s)", s.path, n)
		}
	}
}

// assertListenerClosed proves the listener is gone: its accept loop has ended,
// its socket file is unlinked and nothing accepts at the path.
func assertListenerClosed(t *testing.T, s *boundSocket) {
	t.Helper()
	select {
	case <-s.done:
	default:
		t.Fatalf("%s is still accepting", s.path)
	}
	if _, err := os.Lstat(s.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s was not unlinked (err=%v)", s.path, err)
	}
	if c, err := net.DialTimeout("unix", s.path, time.Second); err == nil {
		c.Close()
		t.Fatalf("something still accepts at %s", s.path)
	}
}

// packSnapshot is everything that identifies a packed artifact, in comparable
// form; it is what the child returns and what the parent asserts on.
type packSnapshot struct {
	canonical   string
	digest      string
	paths       []string
	blobDigests []string
	blobBytes   map[string][]byte
}

func snapshotOfPacked(p *Packed) (packSnapshot, error) {
	canonical, err := Canonical(p.Manifest.Value)
	if err != nil {
		return packSnapshot{}, err
	}
	s := packSnapshot{canonical: string(canonical), digest: p.ArtifactDigest, blobBytes: map[string][]byte{}}
	for _, f := range p.Manifest.Files {
		s.paths = append(s.paths, string(f.Path))
	}
	for d, b := range p.Blobs {
		s.blobDigests = append(s.blobDigests, d)
		s.blobBytes[d] = append([]byte(nil), b...)
	}
	sort.Slice(s.blobDigests, func(i, j int) bool { return CompareStrings(s.blobDigests[i], s.blobDigests[j]) < 0 })
	return s, nil
}

func snapshotOf(t *testing.T, p *Packed) packSnapshot {
	t.Helper()
	s, err := snapshotOfPacked(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func assertSameSnapshot(t *testing.T, a, b packSnapshot) {
	t.Helper()
	if a.canonical != b.canonical || a.digest != b.digest {
		t.Fatalf("identity changed:\n before %s %s\n after  %s %s", a.digest, a.canonical, b.digest, b.canonical)
	}
	if strings.Join(a.paths, ",") != strings.Join(b.paths, ",") {
		t.Fatalf("file order changed: %v vs %v", a.paths, b.paths)
	}
	if strings.Join(a.blobDigests, ",") != strings.Join(b.blobDigests, ",") {
		t.Fatalf("blob digest set changed: %v vs %v", a.blobDigests, b.blobDigests)
	}
	if len(a.blobBytes) != len(b.blobBytes) {
		t.Fatalf("blob count changed: %d vs %d", len(a.blobBytes), len(b.blobBytes))
	}
	for d, bb := range a.blobBytes {
		if !bytes.Equal(bb, b.blobBytes[d]) {
			t.Fatalf("blob %s bytes changed", d)
		}
	}
}

// assertMatchesAnchor checks a snapshot against the anchor's UNCHANGED static
// expectations: canonical bytes, artifact digest, file order and blob digest
// set; and the blob bytes — every blob hashes to its digest, and the bytes of
// every anchor input file are present under that file's digest.
func assertMatchesAnchor(t *testing.T, s packSnapshot, expected expectedFields, files []setupFile) {
	t.Helper()
	if s.canonical != *expected.CanonicalJSON {
		t.Fatalf("canonical mismatch at byte %d:\n expected %q\n actual   %q", firstDiff([]byte(s.canonical), []byte(*expected.CanonicalJSON)), *expected.CanonicalJSON, s.canonical)
	}
	if s.digest != expected.ArtifactDigest || Digest([]byte(s.canonical)) != expected.ArtifactDigest {
		t.Fatalf("artifact digest %s (canonical hashes to %s) != anchor %s", s.digest, Digest([]byte(s.canonical)), expected.ArtifactDigest)
	}
	if want := anchorPaths(t, expected); strings.Join(s.paths, ",") != strings.Join(want, ",") {
		t.Fatalf("file order %v != anchor %v", s.paths, want)
	}
	if strings.Join(s.blobDigests, ",") != strings.Join(expected.BlobDigests, ",") {
		t.Fatalf("blob digests %v != anchor %v", s.blobDigests, expected.BlobDigests)
	}
	for d, b := range s.blobBytes {
		if Digest(b) != d {
			t.Fatalf("blob %s does not hash to its digest", d)
		}
	}
	for _, f := range files {
		data := decodeB64(t, f.ContentBase64)
		if got, ok := s.blobBytes[Digest(data)]; !ok || !bytes.Equal(got, data) {
			t.Fatalf("the bytes of %s are not packed under their digest %s", f.Path, Digest(data))
		}
	}
}

// ---------------------------------------------------------------------------
// Process isolation: every potentially blocking pack call runs in a child under
// an external deadline with kill-and-reap; the child returns a structured result.
// ---------------------------------------------------------------------------

const (
	helperEnv       = "OWA_PACK_NONREGULAR_HELPER"
	helperDirEnv    = "OWA_PACK_NONREGULAR_DIR"
	helperEntryEnv  = "OWA_PACK_NONREGULAR_ENTRYPOINT"
	packDeadline    = 30 * time.Second
	controlDeadline = 2 * time.Second
)

// childPack is the one JSON document the "pack" helper prints.
type childPack struct {
	OK        bool              `json:"ok"`
	Category  string            `json:"category,omitempty"`
	Known     bool              `json:"known,omitempty"`
	Message   string            `json:"message,omitempty"`
	Canonical string            `json:"canonical,omitempty"`
	Digest    string            `json:"digest,omitempty"`
	Paths     []string          `json:"paths,omitempty"`
	Blobs     map[string][]byte `json:"blobs,omitempty"`
}

type childRun struct {
	pid      int
	stdout   string
	stderr   string
	err      error
	timedOut bool
	signaled bool
	signal   syscall.Signal
	gone     bool // the pid can no longer be signalled: exited AND reaped (a zombie still accepts signal 0)
}

// runHelper re-executes the test binary running only the helper, in `mode`,
// under `deadline`. On deadline the child is killed with SIGKILL and reaped by
// Wait; WaitDelay closes any pipes it left open. A timed-out child that was not
// killed by SIGKILL and reaped is a test failure in itself.
func runHelper(t *testing.T, mode, dir, entrypoint string, deadline time.Duration) childRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcessPackNonRegular$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, helperDirEnv+"="+dir, helperEntryEnv+"="+entrypoint)
	cmd.Cancel = func() error { return cmd.Process.Kill() } // SIGKILL at the deadline (the default, stated explicitly)
	cmd.WaitDelay = 5 * time.Second                         // close pipes even if the killed child left them open
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	pid := cmd.Process.Pid
	err := cmd.Wait() // reaps the child
	run := childRun{pid: pid, stdout: stdout.String(), stderr: stderr.String(), err: err, timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		run.signaled, run.signal = true, ws.Signal()
	}
	run.gone = errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	if run.timedOut {
		if !run.signaled || run.signal != syscall.SIGKILL {
			t.Fatalf("timed-out child %d was not killed by SIGKILL: %v", pid, cmd.ProcessState)
		}
		if !run.gone {
			t.Fatalf("timed-out child %d still exists after Wait: it was not reaped", pid)
		}
	}
	return run
}

// packInChild packs dir in a child under packDeadline and returns the child's
// structured result. A child that blocks is killed and reaped and the test
// fails; so does a child that crashes or prints no structured result.
func packInChild(t *testing.T, dir, entrypoint string) childPack {
	t.Helper()
	run := runHelper(t, "pack", dir, entrypoint, packDeadline)
	if run.timedOut {
		t.Fatalf("packing %s produced no result within %v — a special entry was opened; the blocked child %d was killed (%v) and reaped (%v). stderr: %s", dir, packDeadline, run.pid, run.signal, run.gone, run.stderr)
	}
	if run.err != nil {
		t.Fatalf("pack child failed: %v\nstdout: %s\nstderr: %s", run.err, run.stdout, run.stderr)
	}
	if !run.gone {
		t.Fatalf("pack child %d was not reaped", run.pid)
	}
	var res childPack
	if err := json.Unmarshal([]byte(run.stdout), &res); err != nil {
		t.Fatalf("pack child returned no structured result: %q (%s)", run.stdout, run.stderr)
	}
	return res
}

func packedInChild(t *testing.T, res childPack) packSnapshot {
	t.Helper()
	if !res.OK {
		t.Fatalf("packing failed in the child: %s %s", res.Category, res.Message)
	}
	s := packSnapshot{canonical: res.Canonical, digest: res.Digest, paths: res.Paths, blobBytes: res.Blobs}
	for d := range res.Blobs {
		s.blobDigests = append(s.blobDigests, d)
	}
	sort.Slice(s.blobDigests, func(i, j int) bool { return CompareStrings(s.blobDigests[i], s.blobDigests[j]) < 0 })
	return s
}

func failedInChild(t *testing.T, res childPack, want Category) {
	t.Helper()
	if res.OK {
		t.Fatalf("packing unexpectedly succeeded in the child: %s", res.Digest)
	}
	if !res.Known || Category(res.Category) != want {
		t.Fatalf("expected %s, got %q: %s", want, res.Category, res.Message)
	}
}

// TestHelperProcessPackNonRegular is only meaningful when re-executed by
// runHelper; in a normal test run it does nothing. Every mode exits explicitly
// so that nothing but its own output reaches stdout.
func TestHelperProcessPackNonRegular(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv(helperDirEnv)
	switch mode {
	case "pack":
		// The real packer; its complete identity or its error category, as one JSON document.
		var res childPack
		packed, err := PackDirectory(dir, os.Getenv(helperEntryEnv))
		if err != nil {
			cat, known := CategoryOf(err)
			res = childPack{Category: string(cat), Known: known, Message: err.Error()}
		} else if s, serr := snapshotOfPacked(packed); serr != nil {
			res = childPack{Message: "canonicalize: " + serr.Error()}
		} else {
			res = childPack{OK: true, Canonical: s.canonical, Digest: s.digest, Paths: s.paths, Blobs: s.blobBytes}
		}
		if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	case "block":
		// Negative control 1: a plain open of the writer-less FIFO blocks forever.
		os.Stdout.WriteString("opening")
		f, err := os.Open(filepath.Join(dir, "blocked.fifo"))
		if err == nil {
			f.Close()
		}
		os.Stdout.WriteString("unexpectedly returned")
		os.Exit(3)
	case "naivepack":
		// Negative control 2: a SIMULATED REGRESSED PACKER that reads every
		// non-directory entry as if it were a regular file — it blocks on a
		// writer-less FIFO exactly where a regressed walk() would.
		os.Stdout.WriteString("walking")
		var read func(string)
		read = func(d string) {
			entries, _ := os.ReadDir(d)
			for _, e := range entries {
				full := filepath.Join(d, e.Name())
				if e.IsDir() {
					read(full)
					continue
				}
				_, _ = os.ReadFile(full) // a socket fails to open; a writer-less FIFO blocks
			}
		}
		read(dir)
		os.Stdout.WriteString("unexpectedly finished")
		os.Exit(3)
	}
}

var specialFIFOs = []string{"pipe.fifo", "assets/queue.txt", "Ω/notes.html"}
var specialSockets = []string{"s.sock", "assets/n.sock"}

func TestPackSkipsFIFOsAndSocketsWithoutChangingIdentity(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	root := shortTemp(t)
	materialize(t, root, files)
	// Regular files and directories only: nothing here can block, so this one pack
	// runs in-process; it is the reference the child results are compared with.
	packed, err := PackDirectory(root, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotOf(t, packed)
	assertMatchesAnchor(t, before, expected, files)
	for _, rel := range specialFIFOs {
		mkfifo(t, filepath.Join(root, filepath.FromSlash(rel)))
	}
	var sockets []*boundSocket
	for _, rel := range specialSockets {
		sockets = append(sockets, bindSocket(t, filepath.Join(root, filepath.FromSlash(rel))))
	}
	// From here on the tree holds writer-less FIFOs: every pack runs in a child under the deadline.
	after := packedInChild(t, packInChild(t, root, entrypoint))
	assertSameSnapshot(t, before, after)
	assertMatchesAnchor(t, after, expected, files)
	if want := len(anchorPaths(t, expected)); len(after.paths) != want {
		t.Fatalf("expected the anchor's %d entries, got %d", want, len(after.paths))
	}
	for _, rel := range append(append([]string{}, specialFIFOs...), specialSockets...) {
		for _, p := range after.paths {
			if p == "/"+rel {
				t.Fatalf("%s must not be a manifest entry", rel)
			}
		}
	}
	assertNoConnections(t, sockets...)
	// Once more in the presence of the special entries: still deterministic.
	assertSameSnapshot(t, before, packedInChild(t, packInChild(t, root, entrypoint)))
	assertNoConnections(t, sockets...)
}

func TestPackSkippedEntryNeverSatisfiesEntrypoint(t *testing.T) {
	// The two error cases are disjoint and ordered: zero regular-file entries →
	// OWA_INVALID_MANIFEST; otherwise a requested entrypoint that is not among the
	// regular-file entries → OWA_MISSING_ENTRYPOINT. Every tree below holds a
	// writer-less FIFO or a socket named index.html, so every pack runs in a child.
	//
	// Second case: regular files exist, but index.html is only a FIFO.
	missing := shortTemp(t)
	materialize(t, missing, []setupFile{{Path: "assets/app.js", ContentBase64: "Y29uc29sZS5sb2coMSkK"}, {Path: "notes.txt", ContentBase64: "bm90ZXMK"}})
	mkfifo(t, filepath.Join(missing, "index.html"))
	failedInChild(t, packInChild(t, missing, "/index.html"), CatMissingEntrypoint)
	// Second case with the entrypoint present only as a socket.
	missingSocket := shortTemp(t)
	materialize(t, missingSocket, []setupFile{{Path: "a.txt", ContentBase64: "YQo="}})
	s := bindSocket(t, filepath.Join(missingSocket, "index.html"))
	failedInChild(t, packInChild(t, missingSocket, "/index.html"), CatMissingEntrypoint)
	assertNoConnections(t, s)
	// First case: a directory containing ONLY a FIFO named index.html has zero
	// regular-file entries → OWA_INVALID_MANIFEST, unambiguously not OWA_MISSING_ENTRYPOINT.
	onlyFIFO := shortTemp(t)
	mkfifo(t, filepath.Join(onlyFIFO, "index.html"))
	failedInChild(t, packInChild(t, onlyFIFO, "/index.html"), CatInvalidManifest)
	// First case with several special entries (one named index.html) and a nested directory.
	empty := shortTemp(t)
	mkfifo(t, filepath.Join(empty, "index.html"))
	mkfifo(t, filepath.Join(empty, "nested", "pipe"))
	only := bindSocket(t, filepath.Join(empty, "nested", "s.sock"))
	failedInChild(t, packInChild(t, empty, "/index.html"), CatInvalidManifest)
	assertNoConnections(t, only)
}

func TestPackRejectsSymlinksToSpecialEntries(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	root := shortTemp(t)
	materialize(t, root, files)
	outside := shortTemp(t)
	mkfifo(t, filepath.Join(outside, "pipe.fifo"))
	s := bindSocket(t, filepath.Join(outside, "s.sock"))
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ label, target string }{
		{"regular file", filepath.Join(root, "index.html")},
		{"directory", filepath.Join(root, "assets")},
		{"missing target", filepath.Join(root, "does-not-exist")},
		{"external file", filepath.Join(outside, "secret.txt")},
		{"FIFO", filepath.Join(outside, "pipe.fifo")},
		{"Unix-domain socket", filepath.Join(outside, "s.sock")},
	}
	// Each case is its own subtest with its own link, removed when the subtest
	// ends, so one failure cannot pollute the next. Every pack runs in a child
	// under the deadline: should the link rule ever regress to following links,
	// the link to the FIFO would block a regressed packer, and the deadline — not
	// the CI job timeout — is what fails the test.
	for i, tc := range cases {
		link := filepath.Join(root, "link-under-test-"+string(rune('a'+i)))
		t.Run(tc.label, func(t *testing.T) {
			if err := os.Symlink(tc.target, link); err != nil {
				t.Fatalf("symlink to %s: %v", tc.label, err)
			}
			t.Cleanup(func() { os.Remove(link) })
			failedInChild(t, packInChild(t, root, entrypoint), CatSymlink)
		})
	}
	assertNoConnections(t, s)
	// With every link removed the tree packs to the unchanged anchor identity again.
	assertMatchesAnchor(t, packedInChild(t, packInChild(t, root, entrypoint)), expected, files)
}

func TestPackFIFOWithoutWriterDoesNotHang(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	root := shortTemp(t)
	materialize(t, root, files)
	mkfifo(t, filepath.Join(root, "pipe.fifo"))
	mkfifo(t, filepath.Join(root, "assets", "index.html.fifo"))
	packed := packedInChild(t, packInChild(t, root, entrypoint))
	assertMatchesAnchor(t, packed, expected, files)
	for _, p := range packed.paths {
		if p == "/pipe.fifo" || p == "/assets/index.html.fifo" {
			t.Fatalf("%s must not be a manifest entry", p)
		}
	}
}

func TestPackFIFODeadlineHarnessKillsBlockedChild(t *testing.T) {
	root := shortTemp(t)
	mkfifo(t, filepath.Join(root, "blocked.fifo"))
	var s *boundSocket
	// Negative control 1: a child blocked inside open of the FIFO hits the deadline,
	// is killed by SIGKILL and reaped. The listener is bound inside this subtest so
	// that, once the subtest ends, the parent can observe that cleanup registered at
	// bind time ran even though a child had to be killed.
	t.Run("blocked open is killed and reaped", func(t *testing.T) {
		s = bindSocket(t, filepath.Join(root, "s.sock"))
		started := time.Now()
		run := runHelper(t, "block", root, "", controlDeadline)
		if !run.timedOut || run.err == nil {
			t.Fatalf("expected the blocked child to be killed at the deadline (timedOut=%v err=%v out=%q)", run.timedOut, run.err, run.stdout)
		}
		if !run.signaled || run.signal != syscall.SIGKILL {
			t.Fatalf("the child was not killed by SIGKILL: signaled=%v signal=%v", run.signaled, run.signal)
		}
		if !run.gone {
			t.Fatalf("pid %d still exists: the child was not reaped", run.pid)
		}
		if run.stdout != "opening" {
			t.Fatalf("the child should have blocked inside open(2), got %q", run.stdout)
		}
		if time.Since(started) > 25*time.Second {
			t.Fatal("the deadline did not fire promptly")
		}
		select {
		case <-s.done:
			t.Fatal("the listener should stay bound while the child is blocked and killed")
		default:
		}
	})
	if t.Failed() {
		return
	}
	assertListenerClosed(t, s)
	// Negative control 2: a SIMULATED REGRESSED PACKER over a real tree — the anchor's
	// regular files plus the writer-less FIFO — blocks in its read of the FIFO and is
	// killed at the deadline; this is the failure packInChild would report.
	files, _, _ := anchorVector(t)
	materialize(t, root, files)
	started := time.Now()
	run := runHelper(t, "naivepack", root, "", controlDeadline)
	if !run.timedOut || run.err == nil {
		t.Fatalf("expected the simulated regressed packer to be killed at the deadline (timedOut=%v err=%v out=%q)", run.timedOut, run.err, run.stdout)
	}
	if !run.signaled || run.signal != syscall.SIGKILL || !run.gone {
		t.Fatalf("the simulated packer was not killed by SIGKILL and reaped: signaled=%v signal=%v gone=%v", run.signaled, run.signal, run.gone)
	}
	if run.stdout != "walking" {
		t.Fatalf("the simulated packer should have blocked inside its read of the FIFO, got %q", run.stdout)
	}
	if time.Since(started) > 25*time.Second {
		t.Fatal("the deadline did not fire promptly")
	}
}
