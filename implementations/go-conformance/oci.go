package owa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Imported is the result of ReadOCILayout.
type Imported struct {
	Manifest          *Manifest
	ArtifactDigest    string
	OCIManifestDigest string
	Blobs             map[string][]byte // digest -> verified bytes, one entry per distinct digest
}

// ErrLayout marks a transport-local (non-portable) OCI layout failure.
var ErrLayout = errors.New("oci layout")

func layoutErr(message string) error { return &layoutError{message} }

type layoutError struct{ message string }

func (e *layoutError) Error() string { return "oci layout: " + e.message }
func (e *layoutError) Unwrap() error { return ErrLayout }

func blobPath(root, digest string) (string, error) {
	if !IsDigestString(digest) {
		return "", layoutErr("descriptor digest is not a sha256 digest: " + digest)
	}
	return filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), nil
}

// readVerifiedBlob reads blobs/sha256/<hex> and verifies the bytes hash to the
// digest (OWA_CONTENT_DIGEST_MISMATCH) and then, when a size is expected, have
// exactly that length (OWA_CONTENT_SIZE_MISMATCH) — hash before size, as the
// conformance guide states for the reader.
func readVerifiedBlob(root, digest string, size int64, checkSize bool) ([]byte, error) {
	path, err := blobPath(root, digest)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if Digest(data) != digest {
		return nil, fail(CatContentDigestMismatch, "blob bytes do not hash to "+digest)
	}
	if checkSize && int64(len(data)) != size {
		return nil, fail(CatContentSizeMismatch, "blob size does not match the declared size for "+digest)
	}
	return data, nil
}

func writeBlob(root, digest string, data []byte) error {
	path, err := blobPath(root, digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeJSON(path string, v *Value) error {
	data, err := Canonical(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteOCILayout writes the OCI image-layout representation of docs/oci.md: the
// canonical OWA manifest as the config blob (config.digest = OWA artifact
// digest), one layer descriptor PER FILE ENTRY with the mapped descriptor media
// type and the org.opencontainers.image.title / dev.openwebartifact.path
// annotations, the artifact-digest manifest annotation, and an index entry
// named by ref. Source bytes are checked at this boundary — size first, then
// digest, as the corpus pins — and each distinct blob is stored once. The OCI
// manifest digest is returned; it is a representation identity, never the OWA
// artifact identity.
func WriteOCILayout(dir string, m *Manifest, blobs map[string][]byte, ref string) (string, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return "", err
	}
	layoutFile := NewObject()
	layoutFile.Set("imageLayoutVersion", NewString(OCILayoutVersion))
	if err := writeJSON(filepath.Join(dir, "oci-layout"), layoutFile); err != nil {
		return "", err
	}

	configBytes, err := Canonical(m.Value)
	if err != nil {
		return "", err
	}
	configDigest := Digest(configBytes)
	if err := writeBlob(dir, configDigest, configBytes); err != nil {
		return "", err
	}

	layers := NewArray()
	for _, f := range m.Files {
		body, ok := blobs[f.Digest]
		if !ok {
			return "", layoutErr("source blob missing for " + f.Digest)
		}
		if int64(len(body)) != f.Size {
			return "", fail(CatContentSizeMismatch, "source blob size does not match the manifest for "+f.Digest)
		}
		if Digest(body) != f.Digest {
			return "", fail(CatContentDigestMismatch, "source blob bytes do not hash to "+f.Digest)
		}
		if err := writeBlob(dir, f.Digest, body); err != nil {
			return "", err
		}
		pathText, ok := f.Path.GoString()
		if !ok {
			return "", layoutErr("artifact path is not representable in UTF-8")
		}
		mediaText, _ := f.MediaType.GoString()
		annotations := NewObject()
		annotations.Set(AnnotationTitle, NewString(strings.TrimPrefix(pathText, "/")))
		annotations.Set(AnnotationPath, NewString(pathText))
		layer := NewObject()
		layer.Set("mediaType", NewString(LayerMediaType(mediaText)))
		layer.Set("digest", NewString(f.Digest))
		layer.Set("size", NewNumber(float64(f.Size)))
		layer.Set("annotations", annotations)
		layers.Array = append(layers.Array, layer)
	}

	config := NewObject()
	config.Set("mediaType", NewString(OWAMediaType))
	config.Set("digest", NewString(configDigest))
	config.Set("size", NewNumber(float64(len(configBytes))))
	manifestAnnotations := NewObject()
	manifestAnnotations.Set(AnnotationArtifact, NewString(configDigest))
	ociManifest := NewObject()
	ociManifest.Set("schemaVersion", NewNumber(2))
	ociManifest.Set("mediaType", NewString(OCIImageManifest))
	ociManifest.Set("artifactType", NewString(OWAMediaType))
	ociManifest.Set("config", config)
	ociManifest.Set("layers", layers)
	ociManifest.Set("annotations", manifestAnnotations)
	ociBytes, err := Canonical(ociManifest)
	if err != nil {
		return "", err
	}
	ociDigest := Digest(ociBytes)
	if err := writeBlob(dir, ociDigest, ociBytes); err != nil {
		return "", err
	}

	descriptorAnnotations := NewObject()
	descriptorAnnotations.Set(AnnotationRefName, NewString(ref))
	descriptorAnnotations.Set(AnnotationArtifact, NewString(configDigest))
	descriptor := NewObject()
	descriptor.Set("mediaType", NewString(OCIImageManifest))
	descriptor.Set("digest", NewString(ociDigest))
	descriptor.Set("size", NewNumber(float64(len(ociBytes))))
	descriptor.Set("artifactType", NewString(OWAMediaType))
	descriptor.Set("annotations", descriptorAnnotations)
	index := NewObject()
	index.Set("schemaVersion", NewNumber(2))
	index.Set("mediaType", NewString(OCIImageIndex))
	index.Set("manifests", NewArray(descriptor))
	if err := writeJSON(filepath.Join(dir, "index.json"), index); err != nil {
		return "", err
	}
	return ociDigest, nil
}

func stringField(obj *Value, key string) (string, bool) {
	v := obj.Get(key)
	if v == nil || v.Kind != KindString {
		return "", false
	}
	return v.Str.GoString()
}

func numberField(obj *Value, key string) (float64, bool) {
	v := obj.Get(key)
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	return v.Number, true
}

func parseJSONFile(path string) (*Value, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data))
}

// ReadOCILayout imports the layout under dir for the given ref, re-verifying
// everything docs/oci.md lists: layout version, index descriptor media type,
// OCI manifest bytes (hash, then declared size), artifactType, config media
// type, config bytes (hash, then size), the config's canonical artifact digest
// against config.digest and the artifact-digest annotation, then — per file
// entry — the descriptor selected by its dev.openwebartifact.path annotation
// (path-aware, duplicate claims are ambiguous, digest-only fallback only for a
// unique digest with a single annotation-less layer, one descriptor per entry),
// its digest, size and mapped media type, and the blob bytes' hash and length.
func ReadOCILayout(dir string, ref string) (*Imported, error) {
	layoutFile, err := parseJSONFile(filepath.Join(dir, "oci-layout"))
	if err != nil {
		return nil, err
	}
	if version, ok := stringField(layoutFile, "imageLayoutVersion"); !ok || version != OCILayoutVersion {
		return nil, layoutErr("unsupported imageLayoutVersion")
	}
	index, err := parseJSONFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	manifests := index.Get("manifests")
	if manifests == nil || manifests.Kind != KindArray {
		return nil, layoutErr("index.json has no manifests array")
	}
	var descriptor *Value
	for _, d := range manifests.Array {
		if d.Kind != KindObject {
			continue
		}
		if ann := d.Get("annotations"); ann != nil && ann.Kind == KindObject {
			if name, ok := stringField(ann, AnnotationRefName); ok && name == ref {
				descriptor = d
				break
			}
		}
	}
	if descriptor == nil {
		return nil, layoutErr("reference not found in index.json: " + ref)
	}
	if mt, ok := stringField(descriptor, "mediaType"); !ok || mt != OCIImageManifest {
		return nil, layoutErr("index descriptor is not an OCI image manifest")
	}
	ociDigest, ok := stringField(descriptor, "digest")
	if !ok {
		return nil, layoutErr("index descriptor has no digest")
	}
	ociSize, ok := numberField(descriptor, "size")
	if !ok {
		return nil, layoutErr("index descriptor has no size")
	}
	ociBytes, err := readVerifiedBlob(dir, ociDigest, int64(ociSize), true)
	if err != nil {
		return nil, err
	}
	ociManifest, err := Parse(string(ociBytes))
	if err != nil {
		return nil, err
	}
	if ociManifest.Kind != KindObject {
		return nil, layoutErr("OCI manifest is not an object")
	}
	if at, ok := stringField(ociManifest, "artifactType"); !ok || at != OWAMediaType {
		return nil, layoutErr("not an Open Web Artifact (artifactType)")
	}
	config := ociManifest.Get("config")
	if config == nil || config.Kind != KindObject {
		return nil, layoutErr("OCI manifest has no config descriptor")
	}
	if mt, ok := stringField(config, "mediaType"); !ok || mt != OWAMediaType {
		return nil, layoutErr("config is not an OWA manifest")
	}
	configDigest, ok := stringField(config, "digest")
	if !ok {
		return nil, layoutErr("config descriptor has no digest")
	}
	configSize, ok := numberField(config, "size")
	if !ok {
		return nil, layoutErr("config descriptor has no size")
	}
	configBytes, err := readVerifiedBlob(dir, configDigest, int64(configSize), true)
	if err != nil {
		return nil, err
	}
	manifestValue, err := Parse(string(configBytes))
	if err != nil {
		return nil, err
	}
	manifest, err := ValidateManifest(manifestValue)
	if err != nil {
		return nil, err
	}
	artifactDigest, err := ArtifactDigest(manifestValue)
	if err != nil {
		return nil, err
	}
	if artifactDigest != configDigest {
		return nil, layoutErr("OWA artifact digest does not match the config digest")
	}
	if ann := ociManifest.Get("annotations"); ann != nil && ann.Kind == KindObject {
		if claimed, ok := stringField(ann, AnnotationArtifact); ok && claimed != artifactDigest {
			return nil, layoutErr("artifact digest annotation does not match the config")
		}
	}

	selector, err := indexLayers(ociManifest.Get("layers"), manifest)
	if err != nil {
		return nil, err
	}
	verified := map[string][]byte{}
	for _, f := range manifest.Files {
		layer, err := selector.selectLayer(f)
		if err != nil {
			return nil, err
		}
		pathText, _ := f.Path.GoString()
		if d, ok := stringField(layer.value, "digest"); !ok || d != f.Digest {
			return nil, layoutErr("layer digest does not match the file entry " + pathText)
		}
		if size, ok := numberField(layer.value, "size"); !ok || size != float64(f.Size) {
			return nil, fail(CatContentSizeMismatch, "layer size does not match the manifest size for "+pathText)
		}
		mediaText, _ := f.MediaType.GoString()
		if mt, ok := stringField(layer.value, "mediaType"); !ok || mt != LayerMediaType(mediaText) {
			return nil, layoutErr("layer media type is not the mapped descriptor media type for " + pathText)
		}
		if layer.hasPathKey && !(layer.pathOK && layer.path == pathText) {
			return nil, layoutErr("layer path annotation does not match the file entry " + pathText)
		}
		body, seen := verified[f.Digest]
		if !seen {
			body, err = readVerifiedBlob(dir, f.Digest, f.Size, true)
			if err != nil {
				return nil, err
			}
			verified[f.Digest] = body
		} else if int64(len(body)) != f.Size {
			return nil, fail(CatContentSizeMismatch, "blob size does not match the declared size for "+f.Digest)
		}
	}
	return &Imported{Manifest: manifest, ArtifactDigest: artifactDigest, OCIManifestDigest: ociDigest, Blobs: verified}, nil
}

type layerRef struct {
	value      *Value
	digest     string
	hasPathKey bool // the dev.openwebartifact.path KEY is present (any value)
	pathOK     bool // ...and its value is a string
	path       string
}

type layerSelector struct {
	byPath     map[string]*layerRef
	byDigest   map[string][]*layerRef
	digestUses map[string]int
	used       map[*layerRef]bool
}

// indexLayers builds the path-aware descriptor index of docs/oci.md: a
// descriptor LIST, never a digest-keyed set. Two descriptors claiming the same
// dev.openwebartifact.path make the layout ambiguous.
func indexLayers(layers *Value, m *Manifest) (*layerSelector, error) {
	s := &layerSelector{byPath: map[string]*layerRef{}, byDigest: map[string][]*layerRef{}, digestUses: map[string]int{}, used: map[*layerRef]bool{}}
	if layers != nil && layers.Kind == KindArray {
		for _, l := range layers.Array {
			if l.Kind != KindObject {
				continue
			}
			ref := &layerRef{value: l}
			ref.digest, _ = stringField(l, "digest")
			if ann := l.Get("annotations"); ann != nil && ann.Kind == KindObject && ann.Has(AnnotationPath) {
				ref.hasPathKey = true
				if p, ok := stringField(ann, AnnotationPath); ok {
					ref.pathOK, ref.path = true, p
					if _, dup := s.byPath[p]; dup {
						return nil, layoutErr("ambiguous layout: multiple layers claim " + AnnotationPath + " " + p)
					}
					s.byPath[p] = ref
				}
			}
			s.byDigest[ref.digest] = append(s.byDigest[ref.digest], ref)
		}
	}
	for _, f := range m.Files {
		s.digestUses[f.Digest]++
	}
	return s, nil
}

func (s *layerSelector) selectLayer(f *File) (*layerRef, error) {
	pathText, ok := f.Path.GoString()
	if !ok {
		return nil, layoutErr("artifact path is not representable in UTF-8")
	}
	layer := s.byPath[pathText]
	if layer == nil {
		candidates := s.byDigest[f.Digest]
		if len(candidates) == 0 {
			return nil, layoutErr("layer missing for " + pathText)
		}
		// Legacy fallback only when unambiguous: unique digest in the manifest,
		// exactly one layer with that digest, and that layer has NO path key.
		if !(s.digestUses[f.Digest] == 1 && len(candidates) == 1 && !candidates[0].hasPathKey) {
			return nil, layoutErr("layer for " + pathText + " cannot be selected: no descriptor carries its path annotation and digest-only matching is only allowed for a unique digest with a single annotation-less layer")
		}
		layer = candidates[0]
	}
	if s.used[layer] {
		return nil, layoutErr("one descriptor cannot satisfy two file entries (" + pathText + ")")
	}
	s.used[layer] = true
	return layer, nil
}
