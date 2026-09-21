package owa

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Independent anchors for index reference selection (issue #36), written from
// docs/oci.md "Index reference selection": EXACTLY ONE EXACT MATCH OR FAIL. The
// requested ref is the only selector; a descriptor matches when its annotations
// object carries org.opencontainers.image.ref.name as a STRING exactly equal to
// the ref; zero and duplicate matches fail; descriptor order never breaks a tie;
// there is no "latest" → manifests[0] fallback. These failures are
// transport-local (no portable OWA category), so they are pinned here rather
// than by negative corpus vectors; blob-read-index-exact-ref-selection in
// docs/conformance/v0.2/blob.json is the portable SUCCESS anchor.

type refEntry struct{ path, content, mediaType string }

// testArtifact builds a validated manifest and its blobs from plain entries.
func testArtifact(t *testing.T, entries []refEntry) (*Manifest, map[string][]byte) {
	t.Helper()
	blobs := map[string][]byte{}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		data := []byte(e.content)
		blobs[Digest(data)] = data
		files = append(files, fmt.Sprintf(`{"path":%q,"digest":%q,"size":%d,"mediaType":%q}`, e.path, Digest(data), len(data), e.mediaType))
	}
	text := fmt.Sprintf(`{"specVersion":%q,"artifactType":%q,"entrypoint":%q,"files":[%s],"access":{"visibility":"unlisted"},"lifecycle":{"expiresAt":null}}`, SpecVersion, OWAMediaType, entries[0].path, strings.Join(files, ","))
	v, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ValidateManifest(v)
	if err != nil {
		t.Fatal(err)
	}
	return m, blobs
}

func mustParse(t *testing.T, text string) *Value {
	t.Helper()
	v, err := Parse(text)
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return v
}

// indexDescriptor re-parses the layout's index.json and returns a FRESH copy of
// manifests[0], so every mutation below starts from the writer's descriptor.
func indexDescriptor(t *testing.T, dir string) *Value {
	t.Helper()
	index, err := parseJSONFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifests := index.Get("manifests")
	if manifests == nil || manifests.Kind != KindArray || len(manifests.Array) != 1 {
		t.Fatal("the writer emits exactly one index descriptor")
	}
	return manifests.Array[0]
}

func writeIndex(t *testing.T, dir string, descriptors ...*Value) {
	t.Helper()
	index := NewObject()
	index.Set("schemaVersion", NewNumber(2))
	index.Set("mediaType", NewString(OCIImageIndex))
	index.Set("manifests", NewArray(descriptors...))
	if err := writeJSON(filepath.Join(dir, "index.json"), index); err != nil {
		t.Fatal(err)
	}
}

func withRef(d *Value, ref *Value) *Value {
	d.Get("annotations").Set(AnnotationRefName, ref)
	return d
}

func withoutMember(obj *Value, key string) *Value {
	kept := make([]*Member, 0, len(obj.Members))
	for _, m := range obj.Members {
		if !m.Key.Equal(StrOf(key)) {
			kept = append(kept, m)
		}
	}
	obj.Members = kept
	return obj
}

func withoutRef(d *Value) *Value         { withoutMember(d.Get("annotations"), AnnotationRefName); return d }
func withoutAnnotations(d *Value) *Value { return withoutMember(d, "annotations") }

func expectNotFound(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected reference-not-found, got success", label)
	}
	if !errors.Is(err, ErrRefNotFound) || errors.Is(err, ErrRefAmbiguous) || !errors.Is(err, ErrLayout) {
		t.Fatalf("%s: expected ErrRefNotFound (a layout error), got %v", label, err)
	}
	if _, ok := CategoryOf(err); ok {
		t.Fatalf("%s: reference selection failures carry no portable OWA category: %v", label, err)
	}
}

func expectAmbiguous(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected ambiguous-reference, got success", label)
	}
	if !errors.Is(err, ErrRefAmbiguous) || errors.Is(err, ErrRefNotFound) || !errors.Is(err, ErrLayout) {
		t.Fatalf("%s: expected ErrRefAmbiguous (a layout error), got %v", label, err)
	}
	if _, ok := CategoryOf(err); ok {
		t.Fatalf("%s: reference selection failures carry no portable OWA category: %v", label, err)
	}
}

func TestSelectIndexDescriptorRules(t *testing.T) {
	d := func(ref string) string {
		return fmt.Sprintf(`{"mediaType":%q,"digest":"sha256:%s","size":1,"annotations":{%q:%q}}`, OCIImageManifest, strings.Repeat("0", 64), AnnotationRefName, ref)
	}
	index := func(manifests string) *Value { return mustParse(t, `{"schemaVersion":2,"manifests":`+manifests+`}`) }
	// 1. manifests MUST be an array.
	for _, text := range []string{`{}`, `{"manifests":null}`, `{"manifests":{}}`, `{"manifests":"latest"}`, `[]`, `"x"`} {
		if _, err := selectIndexDescriptor(mustParse(t, text), "latest"); err == nil || !errors.Is(err, ErrLayout) || errors.Is(err, ErrRefNotFound) {
			t.Fatalf("%s: expected a manifests-array layout error, got %v", text, err)
		}
	}
	// The requested ref is the selector. Empty remains a valid explicit library-level string value.
	emptyIndex := index("[" + d("") + "]")
	if got, err := selectIndexDescriptor(emptyIndex, ""); err != nil || got != emptyIndex.Get("manifests").Array[0] {
		t.Fatalf("explicit empty ref must select the exact empty-string annotation: %v", err)
	}
	// 4. exactly one match returns THAT descriptor, wherever it sits.
	for _, tc := range []struct {
		manifests string
		want      int
	}{
		{"[" + d("latest") + "]", 0},
		{"[" + d("v1") + "," + d("latest") + "]", 1},
		{"[" + d("v2") + "," + d("v1") + "," + d("latest") + "," + d("v3") + "]", 2},
		{`[null,"latest",42,true,["latest"],` + d("latest") + "]", 5}, // non-object entries are ignored
	} {
		idx := index(tc.manifests)
		got, err := selectIndexDescriptor(idx, "latest")
		if err != nil || got != idx.Get("manifests").Array[tc.want] {
			t.Fatalf("%s: expected descriptor %d, got %v (%v)", tc.manifests, tc.want, got, err)
		}
	}
	// 5, 8–14. zero matches → not found; none of these matches "latest".
	for _, manifests := range []string{
		`[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("0", 64) + `","size":1}]`, // no annotations
		`[{"annotations":null}]`, `[{"annotations":"latest"}]`, `[{"annotations":["latest"]}]`, `[{"annotations":{}}]`,
		`[{"annotations":{"org.opencontainers.image.title":"latest"}}]`,
		`[{"annotations":{"org.opencontainers.image.ref.name":null}}]`,
		`[{"annotations":{"org.opencontainers.image.ref.name":0}}]`, `[{"annotations":{"org.opencontainers.image.ref.name":1}}]`,
		`[{"annotations":{"org.opencontainers.image.ref.name":true}}]`, `[{"annotations":{"org.opencontainers.image.ref.name":false}}]`,
		`[{"annotations":{"org.opencontainers.image.ref.name":""}}]`,
		`[{"annotations":{"org.opencontainers.image.ref.name":["latest"]}}]`, `[{"annotations":{"org.opencontainers.image.ref.name":{"name":"latest"}}}]`,
		"[" + d("v1") + "]", "[" + d("Latest") + "]", "[" + d("LATEST") + "]", "[" + d(" latest") + "]", "[" + d("latest ") + "]", "[" + d("latest\u00a0") + "]", "[" + d("lätest") + "]",
		"[" + d("v1") + "," + d("v2") + "]",
		`[null,"latest",42,["latest"]]`,
		"[]",
	} {
		_, err := selectIndexDescriptor(index(manifests), "latest")
		expectNotFound(t, err, manifests)
	}
	// 15. requesting "latest" never falls back to manifests[0].
	_, err := selectIndexDescriptor(index("["+d("v1")+"]"), "latest")
	expectNotFound(t, err, "single v1 descriptor requested as latest")
	// 6–7. more than one exact match → ambiguous, in any order, with or without bystanders.
	other := fmt.Sprintf(`{"mediaType":%q,"digest":"sha256:%s","size":2,"annotations":{%q:"latest"}}`, OCIImageManifest, strings.Repeat("f", 64), AnnotationRefName)
	for _, manifests := range []string{
		"[" + d("latest") + "," + d("latest") + "]",
		"[" + d("latest") + "," + other + "]",
		"[" + other + "," + d("latest") + "]",
		"[" + d("v1") + "," + d("latest") + "," + d("v2") + "," + other + "]",
		"[" + d("latest") + "," + d("latest") + "," + other + "]",
	} {
		_, err := selectIndexDescriptor(index(manifests), "latest")
		expectAmbiguous(t, err, manifests)
		if manifests == "["+d("latest")+","+d("latest")+","+other+"]" && !strings.Contains(err.Error(), "3 descriptors") {
			t.Fatalf("the ambiguity error reports the match count: %v", err)
		}
	}
	// A ref that is unique in the same index still selects.
	idx := index("[" + d("latest") + "," + d("v1") + "," + d("latest") + "]")
	if got, err := selectIndexDescriptor(idx, "v1"); err != nil || got != idx.Get("manifests").Array[1] {
		t.Fatalf("unique v1 among duplicate latest: %v", err)
	}
}

func TestIndexRefNoLatestFallback(t *testing.T) {
	dir := t.TempDir()
	m, blobs := testArtifact(t, []refEntry{{"/index.html", "<h1>v1 only</h1>", "text/html; charset=utf-8"}})
	ociDigest, err := WriteOCILayout(dir, m, blobs, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := stringField(indexDescriptor(t, dir).Get("annotations"), AnnotationRefName); !ok || name != "v1" {
		t.Fatal("the writer names its single descriptor by the requested ref (unchanged)")
	}
	_, err = ReadOCILayout(dir, "latest")
	expectNotFound(t, err, "single v1 descriptor read as latest: no first-descriptor fallback")
	_, err = ReadOCILayout(dir, "v2")
	expectNotFound(t, err, "no matching ref")
	imported, err := ReadOCILayout(dir, "v1")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ArtifactDigest(m.Value)
	if imported.ArtifactDigest != want || imported.OCIManifestDigest != ociDigest {
		t.Fatal("the exact ref still imports the written layout")
	}
}

func TestIndexRefMalformedAnnotationsNeverMatch(t *testing.T) {
	dir := t.TempDir()
	m, blobs := testArtifact(t, []refEntry{{"/index.html", "<h1>one</h1>", "text/html; charset=utf-8"}})
	if _, err := WriteOCILayout(dir, m, blobs, "latest"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOCILayout(dir, "latest"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		label  string
		mutate func(*Value) *Value
	}{
		{"no annotations object", withoutAnnotations},
		{"annotations null", func(d *Value) *Value { d.Set("annotations", NewNull()); return d }},
		{"annotations not an object", func(d *Value) *Value { d.Set("annotations", NewString("latest")); return d }},
		{"annotations without the ref.name key", withoutRef},
		{"ref.name null", func(d *Value) *Value { return withRef(d, NewNull()) }},
		{"ref.name number", func(d *Value) *Value { return withRef(d, NewNumber(1)) }},
		{"ref.name true", func(d *Value) *Value { return withRef(d, &Value{Kind: KindBool, Bool: true}) }},
		{"ref.name false", func(d *Value) *Value { return withRef(d, &Value{Kind: KindBool, Bool: false}) }},
		{"ref.name empty string", func(d *Value) *Value { return withRef(d, NewString("")) }},
		{"ref.name another ref", func(d *Value) *Value { return withRef(d, NewString("v1")) }},
		{"ref.name differing only in case", func(d *Value) *Value { return withRef(d, NewString("Latest")) }},
	}
	for _, tc := range cases {
		writeIndex(t, dir, tc.mutate(indexDescriptor(t, dir)))
		_, err := ReadOCILayout(dir, "latest")
		expectNotFound(t, err, tc.label)
		writeIndex(t, dir, indexDescriptor(t, dir)) // the index now holds the mutated descriptor; restore below
		// Restore the writer's descriptor for the next case.
		if _, err := WriteOCILayout(dir, m, blobs, "latest"); err != nil {
			t.Fatal(err)
		}
	}
	// manifests missing or not an array.
	for _, text := range []string{`{"schemaVersion":2,"mediaType":"` + OCIImageIndex + `"}`, `{"schemaVersion":2,"manifests":{}}`} {
		if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOCILayout(dir, "latest"); err == nil || !errors.Is(err, ErrLayout) || errors.Is(err, ErrRefNotFound) {
			t.Fatalf("%s: expected a manifests-array layout error, got %v", text, err)
		}
	}
}

// twoArtifacts writes two complete, importable artifacts into ONE layout
// directory (blobs accumulate; index.json is then composed by hand) and returns
// the writer's descriptors for each.
func twoArtifacts(t *testing.T) (dir string, decoy, target *Manifest, decoyDesc, targetDesc *Value, decoyOCI, targetOCI string) {
	t.Helper()
	dir = t.TempDir()
	decoy, decoyBlobs := testArtifact(t, []refEntry{{"/index.html", "<h1>v1: the decoy</h1>", "text/html; charset=utf-8"}})
	target, targetBlobs := testArtifact(t, []refEntry{
		{"/index.html", "<h1>latest: the target</h1>", "text/html; charset=utf-8"},
		{"/notes.txt", "selected by ref.name, not by position", "text/plain; charset=utf-8"},
	})
	var err error
	if decoyOCI, err = WriteOCILayout(dir, decoy, decoyBlobs, "v1"); err != nil {
		t.Fatal(err)
	}
	decoyDesc = indexDescriptor(t, dir)
	if targetOCI, err = WriteOCILayout(dir, target, targetBlobs, "latest"); err != nil {
		t.Fatal(err)
	}
	targetDesc = indexDescriptor(t, dir)
	if decoyOCI == targetOCI {
		t.Fatal("the two artifacts must differ")
	}
	return
}

func fresh(t *testing.T, d *Value) *Value {
	t.Helper()
	data, err := Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, string(data))
}

func assertTarget(t *testing.T, imported *Imported, target, decoy *Manifest, targetOCI string) {
	t.Helper()
	want, _ := ArtifactDigest(target.Value)
	notWant, _ := ArtifactDigest(decoy.Value)
	if imported.ArtifactDigest != want {
		t.Fatalf("expected the target artifact %s, got %s", want, imported.ArtifactDigest)
	}
	if imported.ArtifactDigest == notWant {
		t.Fatal("the first descriptor (decoy) was selected")
	}
	if imported.OCIManifestDigest != targetOCI {
		t.Fatal("OCI manifest digest is not the target's")
	}
	if len(imported.Manifest.Files) != 2 || len(imported.Blobs) != 2 {
		t.Fatalf("expected 2 files and 2 blobs, got %d and %d", len(imported.Manifest.Files), len(imported.Blobs))
	}
}

func TestIndexRefDuplicateMatchesAreAmbiguous(t *testing.T) {
	dir, _, target, decoyDesc, targetDesc, _, _ := twoArtifacts(t)
	targetWant, _ := ArtifactDigest(target.Value)
	// Identical duplicates of one importable descriptor.
	writeIndex(t, dir, fresh(t, targetDesc), fresh(t, targetDesc))
	_, err := ReadOCILayout(dir, "latest")
	expectAmbiguous(t, err, "identical duplicates")
	if !strings.Contains(err.Error(), "2 descriptors carry "+AnnotationRefName+" latest") {
		t.Fatalf("ambiguity message names the count and ref: %v", err)
	}
	// Two DIFFERENT complete artifacts both claiming latest: neither first nor last wins.
	decoyAsLatest := func() *Value { return withRef(fresh(t, decoyDesc), NewString("latest")) }
	writeIndex(t, dir, decoyAsLatest(), fresh(t, targetDesc))
	_, err = ReadOCILayout(dir, "latest")
	expectAmbiguous(t, err, "decoy first")
	writeIndex(t, dir, fresh(t, targetDesc), decoyAsLatest())
	_, err = ReadOCILayout(dir, "latest")
	expectAmbiguous(t, err, "reversed duplicate order")
	writeIndex(t, dir, withRef(fresh(t, decoyDesc), NewString("v0")), decoyAsLatest(), withRef(fresh(t, targetDesc), NewString("v2")), fresh(t, targetDesc))
	_, err = ReadOCILayout(dir, "latest")
	expectAmbiguous(t, err, "bystanders do not disambiguate")
	// The same index still serves a ref that is unique in it.
	imported, err := ReadOCILayout(dir, "v2")
	if err != nil || imported.ArtifactDigest != targetWant {
		t.Fatalf("unique v2 in an index with duplicate latest: %v", err)
	}
}

func TestIndexRefExactMatchBeatsPosition(t *testing.T) {
	dir, decoy, target, decoyDesc, targetDesc, decoyOCI, targetOCI := twoArtifacts(t)
	// Decoy (v1) first, target (latest) second — the shape of blob-read-index-exact-ref-selection.
	writeIndex(t, dir, fresh(t, decoyDesc), fresh(t, targetDesc))
	imported, err := ReadOCILayout(dir, "latest")
	if err != nil {
		t.Fatal(err)
	}
	assertTarget(t, imported, target, decoy, targetOCI)
	got, err := ReadOCILayout(dir, "v1")
	decoyWant, _ := ArtifactDigest(decoy.Value)
	if err != nil || got.ArtifactDigest != decoyWant || got.OCIManifestDigest != decoyOCI {
		t.Fatalf("the other ref selects the decoy; only the ref decides: %v", err)
	}
	// Reversed: the same ref selects the same artifact.
	writeIndex(t, dir, fresh(t, targetDesc), fresh(t, decoyDesc))
	if imported, err = ReadOCILayout(dir, "latest"); err != nil {
		t.Fatal(err)
	}
	assertTarget(t, imported, target, decoy, targetOCI)
	// Buried among non-object entries and unrelated or malformed descriptors.
	writeIndex(t, dir, NewNull(), NewString("latest"), withRef(fresh(t, decoyDesc), NewString("v0")), fresh(t, decoyDesc), withoutRef(fresh(t, decoyDesc)), withRef(fresh(t, decoyDesc), NewNull()), fresh(t, targetDesc), withRef(fresh(t, decoyDesc), NewString("v2")), NewNumber(42))
	if imported, err = ReadOCILayout(dir, "latest"); err != nil {
		t.Fatal(err)
	}
	assertTarget(t, imported, target, decoy, targetOCI)
	// Remove the only match: nothing positional rescues latest.
	writeIndex(t, dir, fresh(t, decoyDesc), withRef(fresh(t, targetDesc), NewString("v2")))
	_, err = ReadOCILayout(dir, "latest")
	expectNotFound(t, err, "no latest among v1 and v2")
}

func TestIndexRefSelectedDescriptorStillVerified(t *testing.T) {
	dir, decoy, target, decoyDesc, targetDesc, _, targetOCI := twoArtifacts(t)
	oversized := fresh(t, targetDesc)
	size, _ := numberField(oversized, "size")
	oversized.Set("size", NewNumber(size+1))
	writeIndex(t, dir, fresh(t, decoyDesc), oversized)
	if _, err := ReadOCILayout(dir, "latest"); err == nil {
		t.Fatal("selected descriptor size must still be checked")
	} else if cat, ok := CategoryOf(err); !ok || cat != CatContentSizeMismatch {
		t.Fatalf("expected OWA_CONTENT_SIZE_MISMATCH after selection, got %v", err)
	}
	wrongType := fresh(t, targetDesc)
	wrongType.Set("mediaType", NewString(OCIImageIndex))
	writeIndex(t, dir, fresh(t, decoyDesc), wrongType)
	if _, err := ReadOCILayout(dir, "latest"); err == nil || !errors.Is(err, ErrLayout) || errors.Is(err, ErrRefNotFound) {
		t.Fatalf("selected descriptor media type must still be checked: %v", err)
	}
	writeIndex(t, dir, fresh(t, decoyDesc), fresh(t, targetDesc))
	imported, err := ReadOCILayout(dir, "latest")
	if err != nil {
		t.Fatal(err)
	}
	assertTarget(t, imported, target, decoy, targetOCI)
}
