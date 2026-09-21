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

// packMediaTypes is the fixed extension → OWA mediaType table of the pack
// operation (spec-v0.2.md "Directory packing" → "Media type assignment",
// issue #33). The table is closed by the specification: nothing outside it is
// mapped, no host or OS MIME database is consulted (this file must never import
// package mime), file bytes are never inspected, and there are no
// compound-extension rules. Keys are the FOLDED extension (see
// packExtensionKey). This is producer behaviour of directory packing only; a
// manually authored manifest may carry any nonempty mediaType.
var packMediaTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".webp":  "image/webp",
	".gif":   "image/gif",
	".txt":   "text/plain; charset=utf-8",
	".wasm":  "application/wasm",
	".ico":   "image/x-icon",
	".xml":   "application/xml; charset=utf-8",
	".pdf":   "application/pdf",
	".woff":  "font/woff",
	".woff2": "font/woff2",
}

// PackFallbackMediaType is assigned to every packed file whose folded extension
// key is not in packMediaTypes: no extension, a dotfile, a trailing-dot name, or
// any unlisted extension.
const PackFallbackMediaType = "application/octet-stream"

// packExtensionKey implements the specification's portable extension rule on a
// COMPLETE artifact path and reports whether an extension exists:
//
//  1. take the final segment — everything after the final "/";
//  2. find the final U+002E "." in that segment; none → no extension;
//  3. if that "." is the segment's FIRST character there is no extension
//     (".env" and ".html" are dotfiles, not files with an extension);
//  4. otherwise the candidate is the segment from that "." to its end
//     ("foo." → ".", "archive.tar.gz" → ".gz", ".foo.html" → ".html");
//  5. fold ASCII A–Z to a–z in the candidate only — never a locale- or
//     Unicode-aware conversion, and never the path itself ("INDEX.HTML" → ".html").
//
// It is deliberately not filepath.Ext, which treats ".env" as an extension.
// Byte indexing is safe: "/" and "." are ASCII and never occur inside a
// multi-byte UTF-8 sequence, and only the bytes 'A'..'Z' are folded.
func packExtensionKey(path string) (string, bool) {
	segment := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		segment = path[i+1:]
	}
	dot := strings.LastIndexByte(segment, '.')
	if dot <= 0 {
		return "", false
	}
	key := []byte(segment[dot:])
	for i, c := range key {
		if c >= 'A' && c <= 'Z' {
			key[i] = c + ('a' - 'A')
		}
	}
	return string(key), true
}

// packMediaType assigns the pack-time mediaType of a complete artifact path
// from the fixed table, or PackFallbackMediaType.
func packMediaType(path string) string {
	if key, ok := packExtensionKey(path); ok {
		if mt, ok := packMediaTypes[key]; ok {
			return mt
		}
	}
	return PackFallbackMediaType
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
