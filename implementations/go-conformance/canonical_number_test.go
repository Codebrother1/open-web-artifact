package owa

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Independent property anchors for rule 5 number serialization (issue #38).
// The static corpus (canonical-b64-*) is the cross-language oracle and is run
// by TestCorpusCanonicalAndParse without Node or JavaScript. This file proves,
// on this host and without any external oracle:
//   - FormatNumber output re-parses (strconv.ParseFloat) to the identical
//     float64 bit pattern for every finite nonzero value tried;
//   - both signed zeros become "0";
//   - the fixed/scientific boundary is applied consistently with the parsed
//     binary64 value: fixed iff 1e-6 <= |v| < 1e21;
//   - the canonical grammar: lowercase e, explicit exponent sign, no zero
//     padding, one digit before the point, no trailing fractional zeros, no
//     "-0", no "+" on the mantissa;
//   - negation symmetry.
// A deterministic xorshift32 stream (seed 0x4f574132, 4096 finite patterns)
// supplements the hand-picked boundary patterns.

var canonicalNumberGrammar = regexp.MustCompile(`^(?:0|-?(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9]|[1-9](?:\.[0-9]*[1-9])?e[+-][1-9][0-9]*))$`)

func checkCanonicalNumberProperties(t *testing.T, f float64, label string) string {
	t.Helper()
	text, err := FormatNumber(f)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !canonicalNumberGrammar.MatchString(text) {
		t.Fatalf("%s: %q violates the canonical number grammar", label, text)
	}
	if f == 0 {
		if text != "0" {
			t.Fatalf("%s: signed zero must serialize as 0, got %q", label, text)
		}
		return text
	}
	back, err := strconv.ParseFloat(text, 64)
	if err != nil || math.Float64bits(back) != math.Float64bits(f) {
		t.Fatalf("%s: %q does not re-parse to bits %016x (got %016x, %v)", label, text, math.Float64bits(f), math.Float64bits(back), err)
	}
	neg, _ := FormatNumber(-f)
	if f > 0 && neg != "-"+text || f < 0 && "-"+neg != text {
		t.Fatalf("%s: negation symmetry broken: %q vs %q", label, text, neg)
	}
	mag := math.Abs(f)
	scientific := strings.Contains(text, "e")
	if scientific != (mag < 1e-6 || mag >= 1e21) {
		t.Fatalf("%s: %q: fixed notation must be used exactly for 1e-6 <= |v| < 1e21", label, text)
	}
	if scientific {
		exp, err := strconv.Atoi(text[strings.IndexByte(text, 'e')+1:])
		if err != nil || (exp > -7 && exp < 21) {
			t.Fatalf("%s: %q: scientific exponent %d lies inside the fixed range", label, text, exp)
		}
		if strings.Contains(text, "e0") || strings.Contains(text, "e+0") || strings.Contains(text, "e-0") || strings.Contains(text, "E") {
			t.Fatalf("%s: %q: exponent padding or uppercase E", label, text)
		}
	}
	again, _ := FormatNumber(back)
	if again != text {
		t.Fatalf("%s: not idempotent: %q then %q", label, text, again)
	}
	return text
}

func TestCanonicalNumberHardBoundaryBits(t *testing.T) {
	// Hand-written from the rule; the hex bit pattern is the identity under test.
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000001, "5e-324"}, {0x0000000000000002, "1e-323"}, {0x000fffffffffffff, "2.225073858507201e-308"},
		{0x0010000000000000, "2.2250738585072014e-308"}, {0x0010000000000001, "2.225073858507202e-308"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"}, {0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"}, {0x3eb0c6f7a0b5ed8d, "0.000001"}, {0x3eb0c6f7a0b5ed8e, "0.0000010000000000000002"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"}, {0x444b1ae4d6e2ef50, "1e+21"}, {0x444b1ae4d6e2ef51, "1.0000000000000001e+21"},
		{0x4310000000000001, "1125899906842624.2"}, {0x4310000000000003, "1125899906842624.8"}, {0xc310000000000001, "-1125899906842624.2"},
		{0x433fffffffffffff, "9007199254740991"}, {0x4340000000000000, "9007199254740992"}, {0x43e0000000000000, "9223372036854776000"},
		{0x3fb999999999999a, "0.1"}, {0x3fd3333333333334, "0.30000000000000004"}, {0x44b52d02c7e14af6, "1e+23"},
		{0x0000000000000000, "0"}, {0x8000000000000000, "0"},
	}
	for _, tc := range cases {
		f := math.Float64frombits(tc.bits)
		got := checkCanonicalNumberProperties(t, f, "0x"+strconv.FormatUint(tc.bits, 16))
		if got != tc.want {
			t.Fatalf("bits %016x: expected %q, got %q", tc.bits, tc.want, got)
		}
	}
}

func TestCanonicalNumberParseBoundaries(t *testing.T) {
	// Parsing (rule 5, sentence 1-2): decimal input rounds to nearest, ties to
	// even; overflow is rejected; underflow to (signed) zero is finite.
	cases := map[string]uint64{
		"1.00000000000000011102230246251565404236316680908203125": 0x3ff0000000000000, // exact midpoint -> even
		"1.00000000000000011102230246251565404236316680908203126": 0x3ff0000000000001,
		"9007199254740993": 0x4340000000000000, "9007199254740995": 0x4340000000000002,
		"4503599627370496.5": 0x4330000000000000, "4503599627370497.5": 0x4330000000000002,
		"2.4703282292062327e-324": 0x0000000000000000, "2.4703282292062328e-324": 0x0000000000000001,
		"1.7976931348623158e308": 0x7fefffffffffffff, "1e-400": 0x0000000000000000, "-1e-400": 0x8000000000000000,
		"9.999999999999998e-7": 0x3eb0c6f7a0b5ed8c, "9.999999999999999e-7": 0x3eb0c6f7a0b5ed8d,
	}
	for in, want := range cases {
		v, err := Parse(in)
		if err != nil || v.Kind != KindNumber {
			t.Fatalf("%s: %v", in, err)
		}
		if got := math.Float64bits(v.Number); got != want {
			t.Fatalf("%s: expected bits %016x, got %016x", in, want, got)
		}
	}
	for _, in := range []string{"1.7976931348623159e308", "-1.7976931348623159e308", "2e308"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("%s: expected OWA_INVALID_JSON_VALUE", in)
		} else if cat, _ := CategoryOf(err); cat != CatInvalidJSONValue {
			t.Fatalf("%s: expected OWA_INVALID_JSON_VALUE, got %v", in, err)
		}
	}
}

func TestCanonicalNumberSeededRoundTrip(t *testing.T) {
	// xorshift32, seed 0x4f574132, as documented for the conformance property suite.
	state := uint32(0x4f574132)
	next := func() uint32 {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		return state
	}
	subnormals, scientific := 0, 0
	for i := 0; i < 4096; i++ {
		bits := uint64(next())<<32 | uint64(next())
		exponent := uint64(next() % 0x7ff) // never 0x7ff: finite only
		bits = bits&^(uint64(0x7ff)<<52) | exponent<<52
		f := math.Float64frombits(bits)
		text := checkCanonicalNumberProperties(t, f, "seeded #"+strconv.Itoa(i)+" bits 0x"+strconv.FormatUint(bits, 16))
		if exponent == 0 && f != 0 {
			subnormals++
		}
		if strings.Contains(text, "e") {
			scientific++
		}
	}
	if subnormals == 0 || scientific == 0 {
		t.Fatal("the seeded stream must cover subnormals and scientific notation")
	}
}
