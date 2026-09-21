package owa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const basicDir = "../../docs/test-vectors/basic"

// The four legacy files are immutable and independently hash-pinned in
// docs/conformance/README.md ("Immutable legacy vectors"). These hashes are
// copied from that table, not computed here.
var basicWholeFileSHA256 = map[string]string{
	"artifact-digest.txt": "49d95b7b03b2eb1f367801d95c17a847a0b335653df0a7562ac3b09e537e5925",
	"canonical.json":      "388a9912105ef49dab9d867b44c98f2c0cb2954139580bf56314b6818c206253",
	"index.html":          "f6c64c97726aac94c47f997a6875c727f8a889043393bd398fe008e3edeb63b0",
	"manifest.json":       "af31c7e942204c39a19fa04ff39976bf349328d1595c6bc680b8b7ab7c06bf29",
}

func TestImmutableBasicVectors(t *testing.T) {
	for name, want := range basicWholeFileSHA256 {
		data, err := os.ReadFile(filepath.Join(basicDir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s: whole-file sha256 %s != pinned %s", name, got, want)
		}
	}
	manifestBytes, _ := os.ReadFile(filepath.Join(basicDir, "manifest.json"))
	canonicalBytes, _ := os.ReadFile(filepath.Join(basicDir, "canonical.json"))
	digestText, _ := os.ReadFile(filepath.Join(basicDir, "artifact-digest.txt"))
	indexHTML, _ := os.ReadFile(filepath.Join(basicDir, "index.html"))

	v, err := Parse(string(manifestBytes))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ValidateManifest(v)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, canonicalBytes) {
		t.Fatalf("canonical bytes differ from canonical.json at byte %d", firstDiff(canonical, canonicalBytes))
	}
	want := strings.TrimSpace(string(digestText))
	if got := Digest(canonical); got != want {
		t.Fatalf("artifact digest %s != published %s", got, want)
	}
	// The published artifact digest is the sha256 of canonical.json's bytes too.
	if Digest(canonicalBytes) != want {
		t.Fatal("artifact-digest.txt does not hash canonical.json")
	}
	if len(m.Files) != 1 || m.Files[0].Digest != Digest(indexHTML) || m.Files[0].Size != int64(len(indexHTML)) {
		t.Fatalf("manifest file entry does not describe index.html (%s, %d bytes)", Digest(indexHTML), len(indexHTML))
	}
}
