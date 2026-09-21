package owa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Independent anchors for pack-time media-type assignment (issue #33), written
// from spec-v0.2.md "Directory packing" → "Media type assignment" — not from
// the reference implementation and not from the code under test. The corpus
// (pack-media-type-*) is the stronger cross-language proof; these anchors pin
// the rule itself on strings, so they also cover names a filesystem may refuse
// to materialize (a trailing dot on Windows).

// The complete published table, hand-copied from the specification.
var specPackTable = map[string]string{
	".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".svg":  "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".webp": "image/webp", ".gif": "image/gif",
	".txt":  "text/plain; charset=utf-8",
	".wasm": "application/wasm",
	".ico":  "image/x-icon",
	".xml":  "application/xml; charset=utf-8",
	".pdf":  "application/pdf",
	".woff": "font/woff", ".woff2": "font/woff2",
}

const octetStream = "application/octet-stream"

// asciiUpper is a test-local ASCII-only upper-casing so the expectation does
// not depend on the folding code under test.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func TestPackMediaTypeFullTable(t *testing.T) {
	if len(specPackTable) != 19 {
		t.Fatalf("the specification table has 19 extensions, test copy has %d", len(specPackTable))
	}
	if len(packMediaTypes) != len(specPackTable) {
		t.Fatalf("implementation table has %d entries, specification has %d", len(packMediaTypes), len(specPackTable))
	}
	for ext, want := range specPackTable {
		for _, path := range []string{
			"/x" + ext,                           // root
			"/dir/sub/x" + ext,                   // nested
			"/x" + asciiUpper(ext),               // all uppercase → folded
			"/DIR/X" + asciiUpper(ext),           // uppercase everywhere; only the key is folded
			"/a.b" + ext,                         // multiple dots: final suffix only
			"/.hidden" + ext,                     // dotfile WITH a later dot has an extension
			"/x.." + ext[1:],                     // consecutive dots: "x..html" → ".html"
			"/x" + ext[:2] + asciiUpper(ext[2:]), // mixed case
		} {
			if got := packMediaType(path); got != want {
				t.Fatalf("%q: expected %q, got %q", path, want, got)
			}
		}
	}
}

func TestPackMediaTypeFallback(t *testing.T) {
	for _, path := range []string{
		"/README", "/Makefile", "/dir/LICENSE", // no dot
		"/.env", "/.html", "/.gitignore", "/dir/.env", "/.PNG", // dotfile: the leading dot alone is not an extension
		"/file.", "/dir/name.", "/x..", "/.a.", // trailing dot: the extension is "." and unlisted
		"/file.xyz", "/x.unknown", // unlisted extension
		"/archive.tar.gz", "/archive.json.gz", "/page.html.bak", "/image.png.orig", // unlisted FINAL extension, no compound rules
		"/vendor.json/LICENSE", "/assets.css/readme", // only the final segment is examined
		"/x.zip", "/x.mp4", "/x.csv", "/x.md", "/x.avif", "/x.mp3", "/x.ttf", "/x.otf", "/x.map", "/x.webmanifest", // known to host MIME databases, NOT to this table
		"/page.ｈｔｍｌ", "/x.HTMİ", "/x.htmｌ", // non-ASCII letters are never folded onto ASCII keys
		"/x.html ", "/x.html\t", "/x. html", // whitespace is an ordinary character
	} {
		if got := packMediaType(path); got != octetStream {
			t.Fatalf("%q: expected %q, got %q", path, octetStream, got)
		}
	}
}

func TestPackExtensionKeyAlgorithm(t *testing.T) {
	cases := map[string]string{ // complete artifact path → folded key, "" = no extension
		"/index.html": ".html", "/INDEX.HTML": ".html", "/archive.tar.gz": ".gz", "/archive.tar.JSON": ".json",
		"/foo.": ".", "/foo..txt": ".txt", "/.foo.html": ".html", "/.env": "", "/.html": "", "/README": "",
		"/dir/.env": "", "/vendor.json/LICENSE": "", "/App.MJS": ".mjs", "/IMAGE.PNG": ".png", "/a/b/c.Woff2": ".woff2",
		"/中/copy.txt": ".txt", "/\U0001F331/notes.TXT": ".txt", "/.css": ".css", "/x.ÄÖ": ".ÄÖ", // non-ASCII stays as is
	}
	for path, want := range cases {
		got, ok := packExtensionKey(path)
		if want == "" {
			if ok {
				t.Fatalf("%q: expected no extension, got %q", path, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("%q: expected key %q, got %q (ok=%v)", path, want, got, ok)
		}
	}
	// filepath.Ext is NOT the rule: it reports ".env" as an extension.
	if filepath.Ext("/.env") != ".env" {
		t.Log("note: filepath.Ext changed; the portable rule is still implemented independently")
	}
	if _, ok := packExtensionKey("/.env"); ok {
		t.Fatal("a dotfile has no extension under the portable rule")
	}
}

// The rule must depend on nothing but the path string: no host MIME database,
// no environment, no file bytes. Guard the import list so a refactor cannot
// quietly reach for package mime (which reads /etc/mime.types and OS registries).
func TestPackMediaTypeConsultsNoHostMIMEDatabase(t *testing.T) {
	src, err := os.ReadFile("pack.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"mime\"", "mime.TypeByExtension", "mime.AddExtensionType", "os.Getenv"} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("pack.go must not use %s", forbidden)
		}
	}
	// Behavioural counterpart: bytes are irrelevant, only the name decides.
	root := t.TempDir()
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	for name, data := range map[string][]byte{
		"index.html": png,                                                     // PNG bytes, .html name
		"logo.png":   []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n"), // SVG text, .png name
		"README":     []byte("<!doctype html>\n"),
		"data.zip":   []byte("PK\x03\x04"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packed, err := PackDirectory(root, "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"/README": octetStream, "/data.zip": octetStream, "/index.html": "text/html; charset=utf-8", "/logo.png": "image/png"}
	if len(packed.Manifest.Files) != len(want) {
		t.Fatalf("expected %d files, got %d", len(want), len(packed.Manifest.Files))
	}
	for _, f := range packed.Manifest.Files {
		if got := string(f.MediaType); got != want[string(f.Path)] {
			t.Fatalf("%s: expected %q, got %q", string(f.Path), want[string(f.Path)], got)
		}
	}
}
