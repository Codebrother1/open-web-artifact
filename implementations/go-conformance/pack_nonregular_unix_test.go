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
// No Node or JavaScript is involved.

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

// bindSocket binds a Unix-domain socket at path and counts connection attempts;
// close() stops accepting and unlinks the socket file on every exit path.
type boundSocket struct {
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
		t.Fatalf("bind socket %s: %v", path, err)
	}
	s := &boundSocket{ln: ln, done: make(chan struct{})}
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
	s.ln.Close() // unlinks the socket file
	<-s.done
}

type packSnapshot struct {
	canonical   string
	digest      string
	paths       []string
	blobDigests []string
	blobBytes   map[string][]byte
}

func snapshotOf(t *testing.T, p *Packed) packSnapshot {
	t.Helper()
	canonical, err := Canonical(p.Manifest.Value)
	if err != nil {
		t.Fatal(err)
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
	for d, bb := range a.blobBytes {
		if !bytes.Equal(bb, b.blobBytes[d]) {
			t.Fatalf("blob %s bytes changed", d)
		}
	}
}

func assertMatchesAnchor(t *testing.T, p *Packed, expected expectedFields) {
	t.Helper()
	checkCanonical(t, p.Manifest.Value, *expected.CanonicalJSON, expected.ArtifactDigest)
	if p.ArtifactDigest != expected.ArtifactDigest {
		t.Fatalf("artifact digest %s != anchor %s", p.ArtifactDigest, expected.ArtifactDigest)
	}
	var digests []string
	for d := range p.Blobs {
		digests = append(digests, d)
	}
	sort.Slice(digests, func(i, j int) bool { return CompareStrings(digests[i], digests[j]) < 0 })
	if strings.Join(digests, ",") != strings.Join(expected.BlobDigests, ",") {
		t.Fatalf("blob digests %v != anchor %v", digests, expected.BlobDigests)
	}
}

var specialFIFOs = []string{"pipe.fifo", "assets/queue.txt", "Ω/notes.html"}
var specialSockets = []string{"s.sock", "assets/n.sock"}

func TestPackSkipsFIFOsAndSocketsWithoutChangingIdentity(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	root := shortTemp(t)
	materialize(t, root, files)
	before, err := PackDirectory(root, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	assertMatchesAnchor(t, before, expected)
	for _, rel := range specialFIFOs {
		mkfifo(t, filepath.Join(root, filepath.FromSlash(rel)))
	}
	var sockets []*boundSocket
	for _, rel := range specialSockets {
		sockets = append(sockets, bindSocket(t, filepath.Join(root, filepath.FromSlash(rel))))
	}
	after, err := PackDirectory(root, entrypoint)
	if err != nil {
		t.Fatalf("packing with special entries present: %v", err)
	}
	assertSameSnapshot(t, snapshotOf(t, before), snapshotOf(t, after))
	assertMatchesAnchor(t, after, expected)
	if len(after.Manifest.Files) != len(expected.BlobDigests)+3 { // 7 entries, 4 distinct blobs in the anchor
		t.Fatalf("expected the anchor's 7 entries, got %d", len(after.Manifest.Files))
	}
	for _, rel := range append(append([]string{}, specialFIFOs...), specialSockets...) {
		if after.Manifest.FileByPath("/"+rel) != nil {
			t.Fatalf("%s must not be a manifest entry", rel)
		}
	}
	for _, s := range sockets {
		if n := atomic.LoadInt32(&s.conns); n != 0 {
			t.Fatalf("the packer connected to a socket %d time(s)", n)
		}
	}
	again, err := PackDirectory(root, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	assertSameSnapshot(t, snapshotOf(t, before), snapshotOf(t, again))
}

func TestPackSkippedEntryNeverSatisfiesEntrypoint(t *testing.T) {
	// Regular assets, but index.html exists only as a FIFO → OWA_MISSING_ENTRYPOINT.
	missing := shortTemp(t)
	materialize(t, missing, []setupFile{{Path: "assets/app.js", ContentBase64: "Y29uc29sZS5sb2coMSkK"}, {Path: "notes.txt", ContentBase64: "bm90ZXMK"}})
	mkfifo(t, filepath.Join(missing, "index.html"))
	if _, err := PackDirectory(missing, "/index.html"); err == nil {
		t.Fatal("a FIFO named index.html must not satisfy the entrypoint")
	} else if cat, _ := CategoryOf(err); cat != CatMissingEntrypoint {
		t.Fatalf("expected OWA_MISSING_ENTRYPOINT, got %v", err)
	}
	// The same with the entrypoint present only as a socket.
	missingSocket := shortTemp(t)
	materialize(t, missingSocket, []setupFile{{Path: "a.txt", ContentBase64: "YQo="}})
	s := bindSocket(t, filepath.Join(missingSocket, "index.html"))
	if _, err := PackDirectory(missingSocket, "/index.html"); err == nil {
		t.Fatal("a socket named index.html must not satisfy the entrypoint")
	} else if cat, _ := CategoryOf(err); cat != CatMissingEntrypoint {
		t.Fatalf("expected OWA_MISSING_ENTRYPOINT, got %v", err)
	}
	if atomic.LoadInt32(&s.conns) != 0 {
		t.Fatal("the packer connected to the socket")
	}
	// Only special entries (one named index.html) → no regular files → OWA_INVALID_MANIFEST.
	empty := shortTemp(t)
	mkfifo(t, filepath.Join(empty, "index.html"))
	mkfifo(t, filepath.Join(empty, "nested", "pipe"))
	only := bindSocket(t, filepath.Join(empty, "nested", "s.sock"))
	if _, err := PackDirectory(empty, "/index.html"); err == nil {
		t.Fatal("a tree with only special entries has no regular files")
	} else if cat, _ := CategoryOf(err); cat != CatInvalidManifest {
		t.Fatalf("expected OWA_INVALID_MANIFEST, got %v", err)
	}
	if atomic.LoadInt32(&only.conns) != 0 {
		t.Fatal("the packer connected to the socket")
	}
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
	for label, target := range map[string]string{
		"regular file":       filepath.Join(root, "index.html"),
		"directory":          filepath.Join(root, "assets"),
		"missing target":     filepath.Join(root, "does-not-exist"),
		"external file":      filepath.Join(outside, "secret.txt"),
		"FIFO":               filepath.Join(outside, "pipe.fifo"),
		"Unix-domain socket": filepath.Join(outside, "s.sock"),
	} {
		link := filepath.Join(root, "link-under-test")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink to %s: %v", label, err)
		}
		_, err := PackDirectory(root, entrypoint)
		if err == nil {
			t.Fatalf("symlink to %s was followed or skipped instead of rejected", label)
		}
		if cat, _ := CategoryOf(err); cat != CatSymlink {
			t.Fatalf("symlink to %s: expected OWA_SYMLINK, got %v", label, err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if atomic.LoadInt32(&s.conns) != 0 {
		t.Fatal("the packer connected to the socket")
	}
	packed, err := PackDirectory(root, entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	assertMatchesAnchor(t, packed, expected)
}

// A FIFO with no writer blocks any open for reading indefinitely, so "the packer
// never opens it" is proven in a SEPARATE process under a real external
// deadline: the test binary re-executes itself running only the helper below;
// on timeout exec.CommandContext kills the child (SIGKILL) and Wait reaps it,
// and the test fails.
const helperEnv = "OWA_PACK_NONREGULAR_HELPER"

func runHelper(t *testing.T, mode, dir, entrypoint string, deadline time.Duration) (out string, err error, timedOut bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcessPackNonRegular$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, "OWA_PACK_NONREGULAR_DIR="+dir, "OWA_PACK_NONREGULAR_ENTRYPOINT="+entrypoint)
	cmd.WaitDelay = 5 * time.Second // close pipes even if the killed child left them open
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if timedOut && cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() {
			t.Fatalf("timed-out child was not killed by a signal: %v", cmd.ProcessState)
		}
	}
	return stdout.String(), err, timedOut
}

// TestHelperProcessPackNonRegular is only meaningful when re-executed by
// runHelper; in a normal test run it does nothing.
func TestHelperProcessPackNonRegular(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv("OWA_PACK_NONREGULAR_DIR")
	switch mode {
	case "pack":
		packed, err := PackDirectory(dir, os.Getenv("OWA_PACK_NONREGULAR_ENTRYPOINT"))
		if err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(2)
		}
		os.Stdout.WriteString(packed.ArtifactDigest)
		os.Exit(0)
	case "block":
		os.Stdout.WriteString("opening")
		f, err := os.Open(filepath.Join(dir, "blocked.fifo")) // blocks forever: no writer
		if err == nil {
			f.Close()
		}
		os.Stdout.WriteString("unexpectedly returned")
		os.Exit(3)
	}
}

func TestPackFIFOWithoutWriterDoesNotHang(t *testing.T) {
	files, entrypoint, expected := anchorVector(t)
	root := shortTemp(t)
	materialize(t, root, files)
	mkfifo(t, filepath.Join(root, "pipe.fifo"))
	mkfifo(t, filepath.Join(root, "assets", "index.html.fifo"))
	out, err, timedOut := runHelper(t, "pack", root, entrypoint, 30*time.Second)
	if timedOut {
		t.Fatal("packing blocked on the writer-less FIFO and was killed after the deadline")
	}
	if err != nil {
		t.Fatalf("child pack failed: %v (%s)", err, out)
	}
	if out != expected.ArtifactDigest {
		t.Fatalf("child packed to %s, anchor is %s", out, expected.ArtifactDigest)
	}
}

func TestPackFIFODeadlineHarnessKillsBlockedChild(t *testing.T) {
	// Self-check of the mechanism: a child that really opens the FIFO blocks, hits
	// the deadline, is killed by SIGKILL and reaped — nothing is left behind.
	root := shortTemp(t)
	mkfifo(t, filepath.Join(root, "blocked.fifo"))
	started := time.Now()
	out, err, timedOut := runHelper(t, "block", root, "", 2*time.Second)
	if !timedOut || err == nil {
		t.Fatalf("expected the blocked child to be killed at the deadline (timedOut=%v err=%v out=%q)", timedOut, err, out)
	}
	if out != "opening" {
		t.Fatalf("the child should have blocked inside open(2), got %q", out)
	}
	if time.Since(started) > 25*time.Second {
		t.Fatal("the deadline did not fire promptly")
	}
}
