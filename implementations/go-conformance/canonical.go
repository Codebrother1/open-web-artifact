package owa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CompareCodePoints orders two code-point sequences lexicographically by their
// numeric code-point values: compare the first unequal value numerically; if
// one sequence is a prefix of the other, the shorter one sorts first. This is
// the relation the specification uses for canonical object keys and for the
// packer's complete artifact paths. It is deliberately NOT locale collation, NOT
// UTF-16 code-unit order, NOT byte order, and applies no normalization or case
// folding. Unpaired surrogates compare by their numeric value.
func CompareCodePoints(a, b []rune) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// CompareStrings applies CompareCodePoints to two Go strings.
func CompareStrings(a, b string) int { return CompareCodePoints([]rune(a), []rune(b)) }

// Canonical encodes a value as the OWA canonical JSON string (UTF-8 bytes, no
// BOM, no trailing newline) following spec-v0.2.md "Canonical manifest encoding"
// rules 1–5: no insignificant whitespace; object keys sorted by code point;
// arrays preserved; exact string escaping; binary64 numbers in the specified
// shortest round-trip decimal form.
func Canonical(v *Value) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Digest returns "sha256:" followed by the lowercase hexadecimal SHA-256 of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ArtifactDigest is sha256(UTF8(canonical JSON)) in the "sha256:<hex>" form.
func ArtifactDigest(v *Value) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return Digest(c), nil
}

func encode(b *bytes.Buffer, v *Value) error {
	switch v.Kind {
	case KindNull:
		b.WriteString("null")
	case KindBool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case KindNumber:
		s, err := FormatNumber(v.Number)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case KindString:
		encodeString(b, v.Str)
	case KindArray:
		b.WriteByte('[')
		for i, item := range v.Array {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case KindObject:
		members := make([]*Member, len(v.Members))
		copy(members, v.Members)
		sort.SliceStable(members, func(i, j int) bool { return CompareCodePoints(members[i].Key, members[j].Key) < 0 })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, m.Key)
			b.WriteByte(':')
			if err := encode(b, m.Value); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fail(CatInvalidJSONValue, "unsupported value kind")
	}
	return nil
}

// encodeString applies rule 4: escape `"` and `\`; short escapes for U+0008,
// U+0009, U+000A, U+000C, U+000D; other U+0000–U+001F as lowercase \u00xx;
// `/` unescaped; every other scalar value literal UTF-8 (including U+2028 and
// U+2029); an unpaired surrogate as a lowercase four-digit \uxxxx escape.
func encodeString(b *bytes.Buffer, s Str) {
	const hexdigits = "0123456789abcdef"
	b.WriteByte('"')
	var buf [utf8.UTFMax]byte
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == 0x08:
			b.WriteString(`\b`)
		case r == 0x09:
			b.WriteString(`\t`)
		case r == 0x0A:
			b.WriteString(`\n`)
		case r == 0x0C:
			b.WriteString(`\f`)
		case r == 0x0D:
			b.WriteString(`\r`)
		case r < 0x20 || (r >= 0xD800 && r <= 0xDFFF):
			b.WriteString(`\u`)
			b.WriteByte(hexdigits[(r>>12)&0xF])
			b.WriteByte(hexdigits[(r>>8)&0xF])
			b.WriteByte(hexdigits[(r>>4)&0xF])
			b.WriteByte(hexdigits[r&0xF])
		default:
			n := utf8.EncodeRune(buf[:], r)
			b.Write(buf[:n])
		}
	}
	b.WriteByte('"')
}

// FormatNumber applies rule 5 to a finite binary64 value: either signed zero is
// "0"; otherwise the shortest decimal digit string that round-trips (closest,
// ties to even) is laid out in fixed notation for 1e-6 <= |v| < 1e21 and in
// scientific notation otherwise, with a lowercase 'e', an explicit '+' for a
// positive exponent, no exponent zero padding, no unnecessary decimal point and
// no trailing fractional zeros.
//
// strconv.FormatFloat(v, 'e', -1, 64) supplies the shortest round-tripping
// significant digits and the decimal exponent; the layout rules are then applied
// here explicitly rather than trusting Go's own 'g'/'e' presentation (which pads
// the exponent to two digits: 1e-07 instead of 1e-7).
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fail(CatInvalidJSONValue, "canonical JSON forbids non-finite numbers")
	}
	if f == 0 {
		return "0", nil // both +0 and -0
	}
	negative := f < 0
	if negative {
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d[.ddd]e±XX
	mant, expText, _ := strings.Cut(e, "e")
	exp10, err := strconv.Atoi(expText)
	if err != nil {
		return "", fail(CatInvalidJSONValue, "unexpected float formatting")
	}
	digits := strings.Replace(mant, ".", "", 1)
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits) // number of significant digits
	n := exp10 + 1   // position of the decimal point relative to the digits
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		exp := n - 1
		sign := "+"
		if exp < 0 {
			sign = "-"
			exp = -exp
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(exp)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(exp)
		}
	}
	if negative {
		out = "-" + out
	}
	return out, nil
}
