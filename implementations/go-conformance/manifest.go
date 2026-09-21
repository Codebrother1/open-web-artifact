package owa

import "math"

// File is the typed view of one validated manifest file entry.
type File struct {
	Path      Str
	Digest    string
	Size      int64
	MediaType Str
}

// Manifest is the typed view of a validated manifest. Value is the untouched
// parsed JSON (canonicalization always works on that, so no field is ever
// added, dropped, normalized or reordered by validation).
type Manifest struct {
	Value          *Value
	SpecVersion    string
	ArtifactType   string
	Entrypoint     Str
	Files          []*File
	HasSPAFallback bool
	SPAFallback    Str
}

// FileByPath returns the file whose path equals path exactly, or nil.
func (m *Manifest) FileByPath(path string) *File { return m.fileByStr(StrOf(path)) }

func (m *Manifest) fileByStr(path Str) *File {
	for _, f := range m.Files {
		if f.Path.Equal(path) {
			return f
		}
	}
	return nil
}

// MaxSafeSize is 2^53 - 1, the largest allowed file size.
const MaxSafeSize = 9007199254740991

var (
	rootKeys      = []string{"specVersion", "artifactType", "entrypoint", "files", "routing", "access", "lifecycle", "annotations"}
	requiredRoot  = []string{"specVersion", "artifactType", "entrypoint", "files"}
	fileKeys      = []string{"path", "digest", "size", "mediaType"}
	routingKeys   = []string{"spaFallback"}
	accessKeys    = []string{"visibility"}
	lifecycleKeys = []string{"expiresAt"}
)

func allowedKeys(obj *Value, allowed []string) bool {
	for _, m := range obj.Members {
		ok := false
		for _, a := range allowed {
			if m.Key.Equal(StrOf(a)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// ValidateManifest checks a parsed JSON value against the v0.2 manifest
// contract (spec-v0.2.md "Manifest", manifest.schema.json and the conformance
// guide's category table). It reads no blobs and never mutates the value.
//
// Category rules, as pinned by the corpus: a non-object manifest, a missing
// required property, an unknown property at any object level, a non-object
// optional container and a non-array/empty files array are OWA_INVALID_MANIFEST;
// a PRESENT property of the wrong type or value uses that property's own
// category (an object with a member named "toString" is still just a wrong type).
func ValidateManifest(v *Value) (*Manifest, error) {
	if v == nil || v.Kind != KindObject {
		return nil, fail(CatInvalidManifest, "manifest must be a JSON object")
	}
	if !allowedKeys(v, rootKeys) {
		return nil, fail(CatInvalidManifest, "manifest has an unknown property")
	}
	for _, k := range requiredRoot {
		if !v.Has(k) {
			return nil, fail(CatInvalidManifest, "manifest is missing required property "+k)
		}
	}
	m := &Manifest{Value: v}

	if sv := v.Get("specVersion"); sv.Kind != KindString || !sv.Str.Equal(StrOf(SpecVersion)) {
		return nil, fail(CatUnsupportedSpecVersion, "unsupported specVersion")
	}
	m.SpecVersion = SpecVersion
	if at := v.Get("artifactType"); at.Kind != KindString || !at.Str.Equal(StrOf(OWAMediaType)) {
		return nil, fail(CatUnsupportedArtifactType, "unsupported artifactType")
	}
	m.ArtifactType = OWAMediaType

	entry, err := ValidateArtifactPath(v.Get("entrypoint"))
	if err != nil {
		return nil, err
	}
	m.Entrypoint = entry

	files := v.Get("files")
	if files.Kind != KindArray || len(files.Array) == 0 {
		return nil, fail(CatInvalidManifest, "files must be a nonempty array")
	}
	for _, fv := range files.Array {
		f, err := validateFile(fv)
		if err != nil {
			return nil, err
		}
		if m.fileByStr(f.Path) != nil {
			return nil, fail(CatDuplicatePath, "duplicate file path")
		}
		m.Files = append(m.Files, f)
	}
	if m.fileByStr(m.Entrypoint) == nil {
		return nil, fail(CatMissingEntrypoint, "entrypoint does not match a file path")
	}

	if v.Has("routing") {
		routing := v.Get("routing")
		if routing.Kind != KindObject {
			return nil, fail(CatInvalidManifest, "routing must be an object")
		}
		if !allowedKeys(routing, routingKeys) {
			return nil, fail(CatInvalidManifest, "routing has an unknown property")
		}
		if routing.Has("spaFallback") {
			fb, err := ValidateArtifactPath(routing.Get("spaFallback"))
			if err != nil {
				return nil, err
			}
			if m.fileByStr(fb) == nil {
				return nil, fail(CatMissingSPAFallback, "spaFallback does not match a file path")
			}
			m.HasSPAFallback = true
			m.SPAFallback = fb
		}
	}
	if v.Has("access") {
		access := v.Get("access")
		if access.Kind != KindObject {
			return nil, fail(CatInvalidManifest, "access must be an object")
		}
		if !allowedKeys(access, accessKeys) {
			return nil, fail(CatInvalidManifest, "access has an unknown property")
		}
		if access.Has("visibility") {
			vis := access.Get("visibility")
			if vis.Kind != KindString || !(vis.Str.Equal(StrOf("public")) || vis.Str.Equal(StrOf("unlisted"))) {
				return nil, fail(CatInvalidVisibility, "visibility must be public or unlisted")
			}
		}
	}
	if v.Has("lifecycle") {
		lifecycle := v.Get("lifecycle")
		if lifecycle.Kind != KindObject {
			return nil, fail(CatInvalidManifest, "lifecycle must be an object")
		}
		if !allowedKeys(lifecycle, lifecycleKeys) {
			return nil, fail(CatInvalidManifest, "lifecycle has an unknown property")
		}
		if lifecycle.Has("expiresAt") {
			exp := lifecycle.Get("expiresAt")
			if exp.Kind != KindNull {
				if exp.Kind != KindString || !ValidExpiry(exp.Str) {
					return nil, fail(CatInvalidExpiry, "expiresAt must be null or an RFC 3339 date-time with an explicit zone")
				}
			}
		}
	}
	if v.Has("annotations") {
		ann := v.Get("annotations")
		if ann.Kind != KindObject {
			return nil, fail(CatInvalidManifest, "annotations must be an object")
		}
		for _, mem := range ann.Members {
			switch mem.Value.Kind {
			case KindNull, KindBool, KindNumber, KindString:
			default:
				return nil, fail(CatInvalidAnnotations, "annotation values must be scalars")
			}
		}
	}
	return m, nil
}

func validateFile(fv *Value) (*File, error) {
	if fv == nil || fv.Kind != KindObject {
		return nil, fail(CatInvalidManifest, "file entry must be an object")
	}
	if !allowedKeys(fv, fileKeys) {
		return nil, fail(CatInvalidManifest, "file entry has an unknown property")
	}
	for _, k := range fileKeys {
		if !fv.Has(k) {
			return nil, fail(CatInvalidManifest, "file entry is missing required property "+k)
		}
	}
	path, err := ValidateArtifactPath(fv.Get("path"))
	if err != nil {
		return nil, err
	}
	digest := fv.Get("digest")
	if digest.Kind != KindString || !isDigestStr(digest.Str) {
		return nil, fail(CatInvalidDigest, "digest must be sha256: followed by 64 lowercase hexadecimal digits")
	}
	size := fv.Get("size")
	if size.Kind != KindNumber || size.Number != math.Trunc(size.Number) || size.Number < 0 || size.Number > MaxSafeSize {
		return nil, fail(CatInvalidSize, "size must be an integer from 0 through 2^53-1")
	}
	media := fv.Get("mediaType")
	if media.Kind != KindString || len(media.Str) == 0 {
		return nil, fail(CatInvalidMediaType, "mediaType must be a nonempty string")
	}
	digestText, _ := digest.Str.GoString() // ASCII by construction
	return &File{Path: path, Digest: digestText, Size: int64(size.Number), MediaType: media.Str}, nil
}

// isDigestStr: exactly "sha256:" + 64 lowercase hexadecimal digits (71 code points).
func isDigestStr(s Str) bool {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if s[i] != rune(prefix[i]) {
			return false
		}
	}
	for _, c := range s[len(prefix):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsDigestString reports whether a Go string is a well-formed sha256 digest.
func IsDigestString(s string) bool { return isDigestStr(StrOf(s)) }

// ValidExpiry implements spec-v0.2.md "Expiry date-time":
// YYYY-MM-DD[Tt]HH:mm:ss[.digits+]([Zz]|[+-]HH:mm), ASCII digits only, exactly
// four year digits, a valid proleptic Gregorian calendar date, hours 00–23,
// minutes and seconds 00–59 (no leap seconds), offset hours 00–23 and offset
// minutes 00–59, nothing before or after. The string is never normalized.
func ValidExpiry(s Str) bool {
	i := 0
	n := len(s)
	digit := func(k int) bool { return k < n && s[k] >= '0' && s[k] <= '9' }
	num := func(start, count int) (int, bool) {
		v := 0
		for k := start; k < start+count; k++ {
			if !digit(k) {
				return 0, false
			}
			v = v*10 + int(s[k]-'0')
		}
		return v, true
	}
	year, ok := num(0, 4)
	if !ok {
		return false
	}
	i = 4
	if i >= n || s[i] != '-' {
		return false
	}
	month, ok := num(i+1, 2)
	if !ok || month < 1 || month > 12 {
		return false
	}
	i += 3
	if i >= n || s[i] != '-' {
		return false
	}
	day, ok := num(i+1, 2)
	if !ok || day < 1 || day > daysIn(year, month) {
		return false
	}
	i += 3
	if i >= n || (s[i] != 'T' && s[i] != 't') {
		return false
	}
	hour, ok := num(i+1, 2)
	if !ok || hour > 23 {
		return false
	}
	i += 3
	if i >= n || s[i] != ':' {
		return false
	}
	minute, ok := num(i+1, 2)
	if !ok || minute > 59 {
		return false
	}
	i += 3
	if i >= n || s[i] != ':' {
		return false
	}
	second, ok := num(i+1, 2)
	if !ok || second > 59 {
		return false
	}
	i += 3
	if i < n && s[i] == '.' {
		i++
		if !digit(i) {
			return false
		}
		for digit(i) {
			i++
		}
	}
	if i >= n {
		return false
	}
	switch s[i] {
	case 'Z', 'z':
		i++
	case '+', '-':
		oh, ok := num(i+1, 2)
		if !ok || oh > 23 {
			return false
		}
		if i+3 >= n || s[i+3] != ':' {
			return false
		}
		om, ok := num(i+4, 2)
		if !ok || om > 59 {
			return false
		}
		i += 6
	default:
		return false
	}
	return i == n
}

func daysIn(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}
