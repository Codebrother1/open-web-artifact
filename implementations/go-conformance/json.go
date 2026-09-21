package owa

import (
	"math"
	"strconv"
	"unicode/utf8"
)

// Kind is the JSON type of a Value.
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Str is a JSON string as a sequence of Unicode code-point values. Unlike a Go
// string it can hold an unpaired surrogate (U+D800–U+DFFF) exactly as the
// specification requires ("preserve an unpaired surrogate as a lowercase
// four-digit \uxxxx escape"), so a JSON text is never altered by parsing.
type Str []rune

// StrOf converts a valid Go (UTF-8) string into a Str.
func StrOf(s string) Str { return Str([]rune(s)) }

// GoString returns the string as Go text. ok is false when the value contains
// an unpaired surrogate, which has no UTF-8 encoding.
func (s Str) GoString() (text string, ok bool) {
	for _, r := range s {
		if r >= 0xD800 && r <= 0xDFFF {
			return "", false
		}
	}
	return string([]rune(s)), true
}

// Equal reports exact code-point equality.
func (s Str) Equal(o Str) bool {
	if len(s) != len(o) {
		return false
	}
	for i := range s {
		if s[i] != o[i] {
			return false
		}
	}
	return true
}

// Member is one object member; Object keeps insertion order so that nothing is
// lost or reordered before canonicalization decides the order.
type Member struct {
	Key   Str
	Value *Value
}

// Value is a parsed JSON value.
type Value struct {
	Kind    Kind
	Bool    bool
	Number  float64
	Str     Str
	Array   []*Value
	Members []*Member // KindObject only, in first-insertion order
}

// Get returns the member with the exact key, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	k := StrOf(key)
	for _, m := range v.Members {
		if m.Key.Equal(k) {
			return m.Value
		}
	}
	return nil
}

// Has reports whether the object has a member with the exact key.
func (v *Value) Has(key string) bool {
	if v == nil || v.Kind != KindObject {
		return false
	}
	k := StrOf(key)
	for _, m := range v.Members {
		if m.Key.Equal(k) {
			return true
		}
	}
	return false
}

// Set adds or replaces a member (replacement keeps the first position).
func (v *Value) Set(key string, val *Value) {
	k := StrOf(key)
	for _, m := range v.Members {
		if m.Key.Equal(k) {
			m.Value = val
			return
		}
	}
	v.Members = append(v.Members, &Member{Key: k, Value: val})
}

// Convenience constructors used by the packer and the OCI writer.
func NewObject() *Value               { return &Value{Kind: KindObject} }
func NewArray(items ...*Value) *Value { return &Value{Kind: KindArray, Array: items} }
func NewString(s string) *Value       { return &Value{Kind: KindString, Str: StrOf(s)} }
func NewNumber(f float64) *Value      { return &Value{Kind: KindNumber, Number: f} }
func NewNull() *Value                 { return &Value{Kind: KindNull} }

// Parse parses exactly one strict JSON text (RFC 8259) into a Value.
//
// The text is taken as-is: a leading byte-order mark, surrounding garbage, a
// second value, comments, single quotes, trailing commas, leading zeros, NaN,
// Infinity, unescaped control characters and bad escapes are syntax failures
// (OWA_INVALID_JSON). Numbers are interpreted as IEEE 754 binary64 with
// round-to-nearest-even; a syntactically valid number that overflows binary64
// is an invalid JSON value (OWA_INVALID_JSON_VALUE), not a syntax error.
// Duplicate member names are outside the portable corpus; this parser keeps the
// last value at the first position and documents that policy rather than
// claiming it is portable.
func Parse(text string) (*Value, error) {
	p := &parser{s: text}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, syntax("unexpected characters after the JSON value")
	}
	return v, nil
}

func syntax(message string) error { return fail(CatInvalidJSON, message) }

type parser struct {
	s string
	i int
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() (*Value, error) {
	if p.i >= len(p.s) {
		return nil, syntax("unexpected end of JSON text")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't':
		return p.literal("true", &Value{Kind: KindBool, Bool: true})
	case c == 'f':
		return p.literal("false", &Value{Kind: KindBool, Bool: false})
	case c == 'n':
		return p.literal("null", &Value{Kind: KindNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, syntax("unexpected character")
	}
}

func (p *parser) literal(word string, v *Value) (*Value, error) {
	if len(p.s)-p.i >= len(word) && p.s[p.i:p.i+len(word)] == word {
		p.i += len(word)
		return v, nil
	}
	return nil, syntax("invalid literal")
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) number() (*Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
		return nil, syntax("invalid number")
	}
	if p.s[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, syntax("invalid number fraction")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, syntax("invalid number exponent")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	token := p.s[start:p.i]
	f, err := strconv.ParseFloat(token, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange && math.IsInf(f, 0) {
			return nil, fail(CatInvalidJSONValue, "number overflows binary64: "+token)
		}
		return nil, syntax("unparseable number " + token)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, fail(CatInvalidJSONValue, "non-finite number: "+token)
	}
	return &Value{Kind: KindNumber, Number: f}, nil
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) hex4() (rune, bool) {
	if len(p.s)-p.i < 4 {
		return 0, false
	}
	var v rune
	for k := 0; k < 4; k++ {
		h, ok := hexVal(p.s[p.i+k])
		if !ok {
			return 0, false
		}
		v = v<<4 | h
	}
	p.i += 4
	return v, true
}

// str parses a JSON string starting at the opening quote.
func (p *parser) str() (Str, error) {
	p.i++ // opening quote
	var out Str
	for {
		if p.i >= len(p.s) {
			return nil, syntax("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return out, nil
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return nil, syntax("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case '/':
				out = append(out, '/')
			case 'b':
				out = append(out, 0x08)
			case 'f':
				out = append(out, 0x0C)
			case 'n':
				out = append(out, 0x0A)
			case 'r':
				out = append(out, 0x0D)
			case 't':
				out = append(out, 0x09)
			case 'u':
				cu, ok := p.hex4()
				if !ok {
					return nil, syntax("invalid \\u escape")
				}
				// A high surrogate immediately followed by an escaped low surrogate
				// is one supplementary code point; anything else stays as-is, so an
				// unpaired surrogate is preserved exactly (never replaced).
				if cu >= 0xD800 && cu <= 0xDBFF && len(p.s)-p.i >= 6 && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
					save := p.i
					p.i += 2
					if lo, ok := p.hex4(); ok && lo >= 0xDC00 && lo <= 0xDFFF {
						cu = 0x10000 + (cu-0xD800)<<10 + (lo - 0xDC00)
					} else {
						p.i = save
					}
				}
				out = append(out, cu)
			default:
				return nil, syntax("invalid escape character")
			}
		case c < 0x20:
			return nil, syntax("unescaped control character in string")
		case c < 0x80:
			out = append(out, rune(c))
			p.i++
		default:
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			if r == utf8.RuneError && size <= 1 {
				return nil, syntax("invalid UTF-8 in JSON text")
			}
			out = append(out, r)
			p.i += size
		}
	}
}

func (p *parser) object() (*Value, error) {
	p.i++ // '{'
	obj := &Value{Kind: KindObject}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, syntax("object member name must be a string")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, syntax("expected ':' after member name")
		}
		p.i++
		p.ws()
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		replaced := false
		for _, m := range obj.Members {
			if m.Key.Equal(key) { // duplicate member name: last value wins (disclosed, non-portable)
				m.Value = val
				replaced = true
				break
			}
		}
		if !replaced {
			obj.Members = append(obj.Members, &Member{Key: key, Value: val})
		}
		p.ws()
		if p.i >= len(p.s) {
			return nil, syntax("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, syntax("expected ',' or '}' in object")
		}
	}
}

func (p *parser) array() (*Value, error) {
	p.i++ // '['
	arr := &Value{Kind: KindArray, Array: []*Value{}}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.ws()
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		arr.Array = append(arr.Array, val)
		p.ws()
		if p.i >= len(p.s) {
			return nil, syntax("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, syntax("expected ',' or ']' in array")
		}
	}
}
