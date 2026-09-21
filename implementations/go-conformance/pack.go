package owa

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Packed is the result of PackDirectory.
type Packed struct {
	Manifest       *Manifest
	ArtifactDigest string
	Blobs          map[string][]byte // digest -> bytes, one entry per distinct digest
}

// packMediaTypes is the extension → OWA mediaType table used by the pack
// operation. The specification does not define media-type detection for
// packing; the portable corpus pins exactly these four extensions through its
// expected manifests, so this implementation maps exactly those (matched
// case-sensitively) and uses application/octet-stream for anything else. That
// fallback and any other extension are outside what the corpus fixes — see
// docs/independent-implementation.md ("Ambiguities").
var packMediaTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".txt":  "text/plain; charset=utf-8",
}

func packMediaType(path string) string {
	if mt, ok := packMediaTypes[filepath.Ext(path)]; ok {
		return mt
	}
	return OCIFallbackMedia
}

// PackDirectory implements spec-v0.2.md "Directory packing (producer ordering)":
// every regular file under dir becomes a file entry whose path is "/" plus the
// slash-joined relative path exactly as the filesystem exposed it (no
// normalization or case folding); symbolic links are rejected (OWA_SYMLINK);
// entries are sorted by CompareCodePoints over the COMPLETE artifact path,
// independent of enumeration order; identical bytes at different paths stay
// distinct entries sharing one blob. The manifest carries the pack defaults
// access.visibility "unlisted" and lifecycle.expiresAt null and is validated
// before it is returned, so an empty directory is OWA_INVALID_MANIFEST and a
// missing entrypoint is OWA_MISSING_ENTRYPOINT.
func PackDirectory(dir string, entrypoint string) (*Packed, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	var entries []*File
	blobs := map[string][]byte{}
	if err := walk(root, root, func(rel string, data []byte) error {
		if !utf8.ValidString(rel) {
			return fail(CatInvalidPath, "filesystem name is not valid UTF-8 and has no portable artifact path")
		}
		path := "/" + filepath.ToSlash(rel)
		if err := ValidatePathString(path); err != nil {
			return err
		}
		digest := Digest(data)
		blobs[digest] = data
		entries = append(entries, &File{Path: StrOf(path), Digest: digest, Size: int64(len(data)), MediaType: StrOf(packMediaType(path))})
		return nil
	}); err != nil {
		return nil, err
	}
	sort.SliceStable(entries, func(i, j int) bool { return CompareCodePoints(entries[i].Path, entries[j].Path) < 0 })

	files := NewArray()
	for _, f := range entries {
		fv := NewObject()
		fv.Set("path", &Value{Kind: KindString, Str: f.Path})
		fv.Set("digest", NewString(f.Digest))
		fv.Set("size", NewNumber(float64(f.Size)))
		fv.Set("mediaType", &Value{Kind: KindString, Str: f.MediaType})
		files.Array = append(files.Array, fv)
	}
	manifest := NewObject()
	manifest.Set("specVersion", NewString(SpecVersion))
	manifest.Set("artifactType", NewString(OWAMediaType))
	manifest.Set("entrypoint", NewString(entrypoint))
	manifest.Set("files", files)
	access := NewObject()
	access.Set("visibility", NewString("unlisted"))
	manifest.Set("access", access)
	lifecycle := NewObject()
	lifecycle.Set("expiresAt", NewNull())
	manifest.Set("lifecycle", lifecycle)

	m, err := ValidateManifest(manifest)
	if err != nil {
		return nil, err
	}
	digest, err := ArtifactDigest(manifest)
	if err != nil {
		return nil, err
	}
	return &Packed{Manifest: m, ArtifactDigest: digest, Blobs: blobs}, nil
}

// walk visits regular files below dir. Directory enumeration order is
// irrelevant to the result (the caller sorts complete paths), but it is made
// deterministic anyway. Symbolic links — to files, directories or nothing — are
// rejected before anything is followed.
func walk(root, dir string, visit func(rel string, data []byte) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.SliceStable(names, func(i, j int) bool { return CompareStrings(names[i], names[j]) < 0 })
	for _, name := range names {
		full := filepath.Join(dir, name)
		info, err := os.Lstat(full)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fail(CatSymlink, "symbolic links are not allowed in an artifact directory")
		case info.IsDir():
			if err := walk(root, full, visit); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			data, err := os.ReadFile(full)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, full)
			if err != nil {
				return err
			}
			if err := visit(strings.TrimPrefix(rel, "./"), data); err != nil {
				return err
			}
		}
	}
	return nil
}
