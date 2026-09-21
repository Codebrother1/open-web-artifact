package owa

import (
	"strings"
	"unicode/utf8"
)

// ResolveRequestPath implements spec-v0.2.md "Safe request-path resolution" on
// the direct request-path argument (not a URL, not a URL parser's output):
//
//  1. percent-decode exactly once and require the result to be strict UTF-8
//     (malformed/short/non-hex escapes, invalid, truncated or overlong UTF-8 and
//     encoded surrogates all yield nil); `+` is not a space; query and fragment
//     characters are not stripped;
//  2. reject a decoded backslash, NUL or any segment exactly `..` — before SPA
//     fallback is considered;
//  3. make the path absolute with one leading `/`, drop empty and `.` segments,
//     keep a trailing slash if the decoded path ended in `/` (an all-empty/dot
//     path is `/`); no normalization or case folding;
//  4. return the exact file match, or the entrypoint file for `/`; only after a
//     direct miss, the configured spaFallback file; otherwise nil.
func ResolveRequestPath(m *Manifest, urlPath string) *File {
	decoded, ok := percentDecodeOnce(urlPath)
	if !ok {
		return nil
	}
	if strings.ContainsAny(decoded, "\\\x00") {
		return nil
	}
	rawSegments := strings.Split(decoded, "/")
	for _, s := range rawSegments {
		if s == ".." {
			return nil
		}
	}
	var segments []string
	for _, s := range rawSegments {
		if s != "" && s != "." {
			segments = append(segments, s)
		}
	}
	path := "/" + strings.Join(segments, "/")
	if len(segments) > 0 && strings.HasSuffix(decoded, "/") {
		path += "/"
	}
	if f := m.FileByPath(path); f != nil {
		return f
	}
	if path == "/" {
		return m.fileByStr(m.Entrypoint)
	}
	if m.HasSPAFallback {
		return m.fileByStr(m.SPAFallback)
	}
	return nil
}

// percentDecodeOnce replaces every %XX with its byte exactly once and requires
// the decoded byte string to be valid UTF-8 (Go's utf8.Valid rejects overlong
// encodings and encoded surrogates).
func percentDecodeOnce(s string) (string, bool) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := hexVal(s[i+1])
		lo, ok2 := hexVal(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		out = append(out, byte(hi<<4|lo))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}
