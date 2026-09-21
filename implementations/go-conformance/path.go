package owa

// ValidateArtifactPath validates a manifest artifact path (spec-v0.2.md
// "Artifact paths"): `/` followed by one or more nonempty segments separated by
// single `/` characters; no segment exactly `.` or `..`; no backslash or NUL
// anywhere. Relative paths, `/` alone, repeated slashes and a trailing slash are
// invalid. Paths are namespace strings: nothing is percent-decoded, normalized
// or case-folded, and the exact input is returned on success.
//
// Any non-string value (null, number, array, object — whatever its member
// names) is OWA_INVALID_PATH; no coercion happens.
func ValidateArtifactPath(v *Value) (Str, error) {
	if v == nil || v.Kind != KindString {
		return nil, fail(CatInvalidPath, "artifact path must be a string")
	}
	return validatePathRunes(v.Str)
}

// ValidatePathString validates a Go string as an artifact path.
func ValidatePathString(s string) error {
	_, err := validatePathRunes(StrOf(s))
	return err
}

func validatePathRunes(r Str) (Str, error) {
	if len(r) == 0 || r[0] != '/' {
		return nil, fail(CatInvalidPath, "artifact path must start with '/'")
	}
	for _, c := range r {
		if c == '\\' || c == 0 {
			return nil, fail(CatInvalidPath, "artifact path must not contain backslash or NUL")
		}
	}
	start := 1
	for i := 1; i <= len(r); i++ {
		if i == len(r) || r[i] == '/' {
			seg := r[start:i]
			if len(seg) == 0 {
				return nil, fail(CatInvalidPath, "artifact path has an empty segment (root, repeated or trailing slash)")
			}
			if isDotSegment(seg) {
				return nil, fail(CatInvalidPath, "artifact path segment must not be '.' or '..'")
			}
			start = i + 1
		}
	}
	return r, nil
}

func isDotSegment(seg Str) bool {
	switch len(seg) {
	case 1:
		return seg[0] == '.'
	case 2:
		return seg[0] == '.' && seg[1] == '.'
	}
	return false
}
