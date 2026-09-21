package owa

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The checked-in static corpus under docs/conformance/v0.2/ is the oracle. This
// harness never calls the JavaScript reference implementation, never shells
// out, and never derives an expected value from the code under test.

const corpusDir = "../../docs/conformance/v0.2"

type corpusFile struct {
	Format      string         `json:"format"`
	SpecVersion string         `json:"specVersion"`
	Operation   string         `json:"operation"`
	Notes       []string       `json:"notes"`
	Vectors     []corpusVector `json:"vectors"`
}

type corpusVector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	InputJSON   *string         `json:"inputJson"`
	Expected    json.RawMessage `json:"expected"`
}

type expectedFields struct {
	ErrorCategory  string          `json:"errorCategory"`
	CanonicalJSON  *string         `json:"canonicalJson"`
	Digest         string          `json:"digest"`
	ArtifactDigest string          `json:"artifactDigest"`
	ValidatedPath  *string         `json:"validatedPath"`
	ResolvedPath   json.RawMessage `json:"resolvedPath"`
	Manifest       json.RawMessage `json:"manifest"`
	BlobDigests    []string        `json:"blobDigests"`
	Blobs          []blobFixture   `json:"blobs"`
}

type blobFixture struct {
	Digest        string `json:"digest"`
	ContentBase64 string `json:"contentBase64"`
}

type setupFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"contentBase64"`
}

type setupSymlink struct {
	Path       string `json:"path"`
	Target     string `json:"target"`
	TargetType string `json:"targetType"`
}

func loadCorpus(t *testing.T, name string) *corpusFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpusDir, name))
	if err != nil {
		t.Fatalf("read corpus %s: %v", name, err)
	}
	var c corpusFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("decode corpus %s: %v", name, err)
	}
	if c.Format != "owa-conformance-v1" || c.SpecVersion != SpecVersion || c.Operation+".json" != name {
		t.Fatalf("%s: unexpected corpus header %q %q %q", name, c.Format, c.SpecVersion, c.Operation)
	}
	seen := map[string]bool{}
	for _, v := range c.Vectors {
		if seen[v.ID] {
			t.Fatalf("%s: duplicate vector id %s", name, v.ID)
		}
		seen[v.ID] = true
		if (v.InputJSON == nil) == (v.Input == nil) {
			t.Fatalf("%s/%s: exactly one of input or inputJson is required", name, v.ID)
		}
	}
	return &c
}

func decodeExpected(t *testing.T, raw json.RawMessage) expectedFields {
	t.Helper()
	var e expectedFields
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode expected: %v", err)
	}
	return e
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		t.Fatalf("fixture bytes are not canonical base64: %q", s)
	}
	return b
}

// checkFailure asserts that err carries exactly the expected category. An
// unrelated error, a setup error, or an unexpected success must not pass.
func checkFailure(t *testing.T, expected expectedFields, err error) {
	t.Helper()
	if expected.ErrorCategory == "" {
		t.Fatalf("unexpected failure: %v", err)
	}
	cat, ok := CategoryOf(err)
	if !ok {
		t.Fatalf("expected category %s but got an unclassified error: %v", expected.ErrorCategory, err)
	}
	if string(cat) != expected.ErrorCategory {
		t.Fatalf("expected category %s, got %s (%v)", expected.ErrorCategory, cat, err)
	}
}

func requireSuccess(t *testing.T, expected expectedFields) {
	t.Helper()
	if expected.ErrorCategory != "" {
		t.Fatalf("expected failure %s but the operation succeeded", expected.ErrorCategory)
	}
}

// checkCanonical compares canonical bytes exactly and independently hashes the
// expected canonical string against the expected digest.
func checkCanonical(t *testing.T, v *Value, expectedCanonical string, expectedDigest string) {
	t.Helper()
	actual, err := Canonical(v)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.Equal(actual, []byte(expectedCanonical)) {
		t.Fatalf("canonical mismatch at byte %d:\n expected %q\n actual   %q", firstDiff(actual, []byte(expectedCanonical)), expectedCanonical, string(actual))
	}
	if got := Digest(actual); got != expectedDigest {
		t.Fatalf("digest mismatch: expected %s, got %s", expectedDigest, got)
	}
	if Digest([]byte(expectedCanonical)) != expectedDigest {
		t.Fatalf("corpus self-check: expected canonicalJson does not hash to %s", expectedDigest)
	}
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return len(a)
}

func mustParseRaw(t *testing.T, raw json.RawMessage) *Value {
	t.Helper()
	v, err := Parse(string(raw))
	if err != nil {
		t.Fatalf("parse fixture value: %v", err)
	}
	return v
}

func sameStructure(t *testing.T, a, b *Value) bool {
	t.Helper()
	ca, err := Canonical(a)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	cb, err := Canonical(b)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return bytes.Equal(ca, cb)
}

func TestCorpusCanonicalAndParse(t *testing.T) {
	for _, name := range []string{"canonical.json", "parse.json"} {
		c := loadCorpus(t, name)
		for _, vec := range c.Vectors {
			vec := vec
			t.Run(vec.ID, func(t *testing.T) {
				expected := decodeExpected(t, vec.Expected)
				v, err := Parse(*vec.InputJSON)
				if err == nil {
					_, err = Canonical(v)
				}
				if err != nil {
					checkFailure(t, expected, err)
					return
				}
				requireSuccess(t, expected)
				checkCanonical(t, v, *expected.CanonicalJSON, expected.Digest)
			})
		}
	}
}

func TestCorpusManifest(t *testing.T) {
	c := loadCorpus(t, "manifest.json")
	for _, vec := range c.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			expected := decodeExpected(t, vec.Expected)
			v, err := Parse(*vec.InputJSON)
			if err == nil {
				_, err = ValidateManifest(v)
			}
			if err != nil {
				checkFailure(t, expected, err)
				return
			}
			requireSuccess(t, expected)
			checkCanonical(t, v, *expected.CanonicalJSON, expected.ArtifactDigest)
			got, err := ArtifactDigest(v)
			if err != nil || got != expected.ArtifactDigest {
				t.Fatalf("artifact digest: %s %v", got, err)
			}
		})
	}
}

func TestCorpusPath(t *testing.T) {
	c := loadCorpus(t, "path.json")
	for _, vec := range c.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			expected := decodeExpected(t, vec.Expected)
			input := mustParseRaw(t, vec.Input)
			validated, err := ValidateArtifactPath(input)
			if err != nil {
				checkFailure(t, expected, err)
				return
			}
			requireSuccess(t, expected)
			if !validated.Equal(StrOf(*expected.ValidatedPath)) {
				t.Fatalf("validated path %q != expected %q", string(validated), *expected.ValidatedPath)
			}
			if !validated.Equal(input.Str) {
				t.Fatal("validated path is not the exact input string")
			}
		})
	}
}

func TestCorpusRequest(t *testing.T) {
	c := loadCorpus(t, "request.json")
	for _, vec := range c.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			expected := decodeExpected(t, vec.Expected)
			var input struct {
				Manifest json.RawMessage `json:"manifest"`
				URLPath  string          `json:"urlPath"`
			}
			if err := json.Unmarshal(vec.Input, &input); err != nil {
				t.Fatal(err)
			}
			m, err := ValidateManifest(mustParseRaw(t, input.Manifest))
			if err != nil {
				t.Fatalf("request fixture manifest must be valid: %v", err)
			}
			requireSuccess(t, expected)
			var resolved *string
			if err := json.Unmarshal(expected.ResolvedPath, &resolved); err != nil {
				t.Fatal(err)
			}
			file := ResolveRequestPath(m, input.URLPath)
			switch {
			case resolved == nil && file != nil:
				t.Fatalf("expected null, resolved %q", string(file.Path))
			case resolved != nil && file == nil:
				t.Fatalf("expected %q, resolved null", *resolved)
			case resolved != nil && !file.Path.Equal(StrOf(*resolved)):
				t.Fatalf("expected %q, resolved %q", *resolved, string(file.Path))
			case resolved != nil && file != m.FileByPath(*resolved):
				t.Fatal("resolver did not return the exact manifest file entry")
			}
		})
	}
}

func materialize(t *testing.T, root string, files []setupFile) {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range files {
		if f.Path == "" || strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\\\x00") {
			t.Fatalf("invalid setup path %q", f.Path)
		}
		for _, seg := range strings.Split(f.Path, "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("invalid setup path segment in %q", f.Path)
			}
		}
		if seen[f.Path] {
			t.Fatalf("duplicate setup path %q", f.Path)
		}
		seen[f.Path] = true
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, decodeB64(t, f.ContentBase64), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorpusPack(t *testing.T) {
	c := loadCorpus(t, "pack.json")
	for _, vec := range c.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			expected := decodeExpected(t, vec.Expected)
			var input struct {
				Files      []setupFile    `json:"files"`
				Symlinks   []setupSymlink `json:"symlinks"`
				Entrypoint string         `json:"entrypoint"`
			}
			if err := json.Unmarshal(vec.Input, &input); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			materialize(t, root, input.Files)
			for _, link := range input.Symlinks {
				full := filepath.Join(root, filepath.FromSlash(link.Path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.FromSlash(link.Target), full); err != nil {
					t.Fatalf("symlink setup: %v", err)
				}
			}
			packed, err := PackDirectory(root, input.Entrypoint)
			if err != nil {
				checkFailure(t, expected, err)
				return
			}
			requireSuccess(t, expected)
			if !sameStructure(t, packed.Manifest.Value, mustParseRaw(t, expected.Manifest)) {
				actual, _ := Canonical(packed.Manifest.Value)
				t.Fatalf("packed manifest differs from expected manifest:\n actual %s", string(actual))
			}
			checkCanonical(t, packed.Manifest.Value, *expected.CanonicalJSON, expected.ArtifactDigest)
			if packed.ArtifactDigest != expected.ArtifactDigest {
				t.Fatalf("artifact digest %s != %s", packed.ArtifactDigest, expected.ArtifactDigest)
			}
			var digests []string
			for d := range packed.Blobs {
				digests = append(digests, d)
			}
			sort.Slice(digests, func(i, j int) bool { return CompareStrings(digests[i], digests[j]) < 0 })
			if strings.Join(digests, ",") != strings.Join(expected.BlobDigests, ",") {
				t.Fatalf("blob digests %v != %v", digests, expected.BlobDigests)
			}
			// Every returned blob equals independently hashed source bytes.
			source := map[string][]byte{}
			for _, f := range input.Files {
				b := decodeB64(t, f.ContentBase64)
				source[Digest(b)] = b
			}
			if len(source) != len(packed.Blobs) {
				t.Fatalf("expected %d distinct blobs, got %d", len(source), len(packed.Blobs))
			}
			for d, b := range packed.Blobs {
				if !bytes.Equal(source[d], b) {
					t.Fatalf("blob %s bytes differ from the source", d)
				}
			}
		})
	}
}

func checkBlobs(t *testing.T, actual map[string][]byte, expected []blobFixture) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("expected %d blobs, got %d", len(expected), len(actual))
	}
	for _, b := range expected {
		want := decodeB64(t, b.ContentBase64)
		if Digest(want) != b.Digest {
			t.Fatalf("corpus self-check: expected blob %s does not hash to its digest", b.Digest)
		}
		got, ok := actual[b.Digest]
		if !ok {
			t.Fatalf("missing blob %s", b.Digest)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("blob %s bytes differ", b.Digest)
		}
	}
}

func TestCorpusBlob(t *testing.T) {
	c := loadCorpus(t, "blob.json")
	for _, vec := range c.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			expected := decodeExpected(t, vec.Expected)
			var input struct {
				Boundary    string          `json:"boundary"`
				Manifest    json.RawMessage `json:"manifest"`
				Blobs       []blobFixture   `json:"blobs"`
				LayoutFiles []setupFile     `json:"layoutFiles"`
			}
			if err := json.Unmarshal(vec.Input, &input); err != nil {
				t.Fatal(err)
			}
			manifestValue := mustParseRaw(t, input.Manifest)
			manifest, err := ValidateManifest(manifestValue)
			if err != nil {
				t.Fatalf("blob fixture manifest must validate (metadata only): %v", err)
			}
			root := t.TempDir()
			var result *Imported
			switch input.Boundary {
			case "oci-write":
				blobs := map[string][]byte{}
				for _, b := range input.Blobs {
					blobs[b.Digest] = decodeB64(t, b.ContentBase64) // keyed by the DECLARED digest
				}
				if _, err = WriteOCILayout(root, manifest, blobs, "latest"); err == nil {
					result, err = ReadOCILayout(root, "latest")
				}
			case "oci-read":
				materialize(t, root, input.LayoutFiles)
				result, err = ReadOCILayout(root, "latest")
			default:
				t.Fatalf("unknown boundary %q", input.Boundary)
			}
			if err != nil {
				checkFailure(t, expected, err)
				return
			}
			requireSuccess(t, expected)
			if !sameStructure(t, result.Manifest.Value, manifestValue) {
				t.Fatal("imported manifest is not structurally equal to input.manifest")
			}
			checkCanonical(t, result.Manifest.Value, *expected.CanonicalJSON, expected.ArtifactDigest)
			if result.ArtifactDigest != expected.ArtifactDigest {
				t.Fatalf("artifact digest %s != %s", result.ArtifactDigest, expected.ArtifactDigest)
			}
			checkBlobs(t, result.Blobs, expected.Blobs)
		})
	}
}

// TestCorpusCoverage pins that every corpus file and every vector is executed
// by exactly one harness above — nothing is silently skipped.
func TestCorpusCoverage(t *testing.T) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	handled := map[string]bool{"canonical.json": true, "parse.json": true, "manifest.json": true, "path.json": true, "request.json": true, "pack.json": true, "blob.json": true}
	total := 0
	for _, e := range entries {
		if !handled[e.Name()] {
			t.Fatalf("corpus file %s has no Go harness", e.Name())
		}
		total += len(loadCorpus(t, e.Name()).Vectors)
	}
	if len(entries) != len(handled) {
		t.Fatalf("expected %d corpus files, found %d", len(handled), len(entries))
	}
	t.Logf("corpus files: %d, vectors: %d", len(entries), total)
}
