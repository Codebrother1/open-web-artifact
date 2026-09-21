package owa

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Independent regression anchors written from the specification text, so a
// future refactor cannot silently substitute byte order, UTF-16 order, locale
// collation, Go's default float formatting or encoding/json behaviour.

func lt(t *testing.T, a, b string, why string) {
	t.Helper()
	if CompareStrings(a, b) >= 0 || CompareStrings(b, a) <= 0 {
		t.Fatalf("expected %q < %q (%s)", a, b, why)
	}
}

func TestCodePointOrderAnchors(t *testing.T) {
	lt(t, "a", "b", "ASCII")
	lt(t, "a", "a0", "a proper prefix sorts first")
	lt(t, "", "a", "the empty string is the shortest prefix")
	lt(t, "A", "a", "no case folding: U+0041 < U+0061")
	lt(t, "10", "2", "no numeric ordering: U+0031 < U+0032")
	lt(t, "z", "Ω", "ASCII before Greek")
	lt(t, "Ω", "中", "Greek before CJK")
	lt(t, "中", "", "CJK before BMP private use")
	// The code-point-versus-UTF-16 anchor: U+E000 = 57344 < U+10000 = 65536,
	// although U+10000's UTF-16 lead surrogate (0xD800) is below 0xE000.
	lt(t, "", "\U00010000", "BMP private use before supplementary BY CODE POINT")
	lt(t, "\U00010000", "\U0001F331", "supplementary values compare numerically")
	lt(t, "￿", "\U00010000", "last BMP code point before the first supplementary one")
	// No normalization: e + U+0301 (two code points) versus U+00E9 (one).
	lt(t, "é", "é", "decomposed before precomposed because U+0065 < U+00E9")
	if CompareStrings("é", "é") == 0 {
		t.Fatal("canonically equivalent strings must remain distinct")
	}
	lt(t, "/a.txt", "/a/x.txt", "complete paths: '.' U+002E < '/' U+002F")
	// UTF-16 code-unit order would put U+10000 first; byte order agrees with
	// code-point order for UTF-8 but NOT for unpaired surrogates, which compare
	// by their numeric value here.
	if CompareCodePoints(Str{0xD800}, Str{0xE000}) >= 0 {
		t.Fatal("an unpaired high surrogate (0xD800) sorts before U+E000 by numeric value")
	}
	for _, s := range []string{"", "a", "/a.txt", "", "\U00010000", "é"} {
		if CompareStrings(s, s) != 0 {
			t.Fatalf("%q must compare equal to itself", s)
		}
	}
}

func TestCanonicalNumberAnchors(t *testing.T) {
	cases := map[string]string{ // JSON input -> canonical output (spec rule 5 and the corpus)
		"-0": "0", "-0.0": "0", "0": "0", "1": "1", "-1": "-1",
		"1e-6": "0.000001", "1e-7": "1e-7", "1e20": "100000000000000000000", "1e21": "1e+21",
		"123.456": "123.456", "0.1": "0.1", "0.100000000000000005": "0.1",
		"333333333.33333329": "333333333.3333333", "9007199254740993": "9007199254740992",
		"-1.5e-10": "-1.5e-10", "5e-324": "5e-324", "1.7976931348623157e308": "1.7976931348623157e+308",
		"100": "100", "1e6": "1000000", "12345678901234567890": "12345678901234567000",
		"0.000001234": "0.000001234", "1.5e300": "1.5e+300",
	}
	for in, want := range cases {
		v, err := Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got, err := FormatNumber(v.Number)
		if err != nil || got != want {
			t.Fatalf("%s: expected %s, got %s (%v)", in, want, got, err)
		}
	}
	for _, in := range []string{"1e400", "-1e400", "1.7976931348623159e308"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("%s: expected OWA_INVALID_JSON_VALUE", in)
		} else if cat, _ := CategoryOf(err); cat != CatInvalidJSONValue {
			t.Fatalf("%s: expected OWA_INVALID_JSON_VALUE, got %v", in, err)
		}
	}
	if _, err := FormatNumber(math.Inf(1)); err == nil {
		t.Fatal("Infinity must be rejected")
	}
	if _, err := FormatNumber(math.NaN()); err == nil {
		t.Fatal("NaN must be rejected")
	}
	// Go's own presentation differs (exponent padding); the layout is applied here.
	if strconv.FormatFloat(1e-7, 'g', -1, 64) == "1e-7" {
		t.Log("note: Go formatting changed; the layout rules are still applied independently")
	}
}

func TestCanonicalStringAnchors(t *testing.T) {
	cases := map[string]string{
		"\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0000\\u001f\"": "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0000\\u001f\"",
		`"café 中 😀   "`:                                "\"café 中 😀   \"",
		`"😀"`:                                          "\"😀\"",
		`"\uD800"`:                                     `"\ud800"`,
		`"\uDC00"`:                                     `"\udc00"`,
		`"a\/b"`:                                       `"a/b"`,
		`{"":2,"\ud800":1}`:                           `{"\ud800":1,"` + "" + `":2}`,
		"{\"aa\":4,\"a\":2,\"\":1,\"a\\u0000\":3}":                        "{\"\":1,\"a\":2,\"a\\u0000\":3,\"aa\":4}",
		`{"z":[3,1,2,{"b":false,"a":null}],"a":{"y":"last","x":"first"}}`: `{"a":{"x":"first","y":"last"},"z":[3,1,2,{"a":null,"b":false}]}`,
	}
	for in, want := range cases {
		v, err := Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got, err := Canonical(v)
		if err != nil || string(got) != want {
			t.Fatalf("%s: expected %s, got %s (%v)", in, want, string(got), err)
		}
	}
	for _, bad := range []string{"", "\ufeff{}", "{'a':1}", "{a:1}", `{"a":1,}`, "{}x", "{}{}", "01", "NaN", "Infinity", "undefined", `"\x20"`, "\"a\nb\"", `"abc`, `{"a":1`} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q must be OWA_INVALID_JSON", bad)
		} else if cat, _ := CategoryOf(err); cat != CatInvalidJSON {
			t.Fatalf("%q: expected OWA_INVALID_JSON, got %v", bad, err)
		}
	}
}

func TestLayerMediaTypeAnchors(t *testing.T) {
	cases := map[string]string{ // docs/oci.md table
		"text/html; charset=utf-8":                     "text/html",
		"text/javascript; charset=utf-8":               "text/javascript",
		"text/css; charset=utf-8":                      "text/css",
		"application/json; charset=utf-8":              "application/json",
		"image/png":                                    "image/png",
		"application/vnd.example.foo+json":             "application/vnd.example.foo+json",
		"application/vnd.openwebartifact.site.v1+json": "application/vnd.openwebartifact.site.v1+json",
		"not actually mime":                            OCIFallbackMedia,
		"   ":                                          OCIFallbackMedia,
		"":                                             OCIFallbackMedia,
		"; charset=utf-8":                              OCIFallbackMedia,
		"text/":                                        OCIFallbackMedia,
		"/html":                                        OCIFallbackMedia,
		"text/html/extra":                              OCIFallbackMedia,
		"text/ht ml":                                   OCIFallbackMedia,
		"text/htmlé":                                   OCIFallbackMedia,
		" \tText/HTML\t ;charset=x":                    "Text/HTML",
		"text/plain ; note=\"a;b\"; charset=utf-8": "text/plain",
	}
	for in, want := range cases {
		if got := LayerMediaType(in); got != want {
			t.Fatalf("%q: expected %q, got %q", in, want, got)
		}
	}
	long := ""
	for i := 0; i < 127; i++ {
		long += "a"
	}
	if LayerMediaType(long+"/"+long) != long+"/"+long {
		t.Fatal("127-character type and subtype are accepted")
	}
	if LayerMediaType(long+"a/plain") != OCIFallbackMedia {
		t.Fatal("128-character type falls back")
	}
}

func TestExpiryAnchors(t *testing.T) {
	valid := []string{"2030-01-02T03:04:05Z", "2030-01-02t03:04:05z", "2030-01-02T03:04:05.123456789Z", "2024-02-29T23:59:59.1Z", "2000-02-29T00:00:00Z", "2030-01-02T03:04:05+23:59", "2030-01-02T03:04:05-00:00"}
	invalid := []string{"", "not-a-date", "2030-01-02", "2030-01-02T03:04:05", "2030-01-02T03:04:05.Z", "2030-01-02T03:04:05Z\n", "1900-02-29T03:04:05Z", "2024-02-30T03:04:05Z", "2023-02-29T00:00:00Z", "2030-01-02T24:00:00Z", "2030-01-02T03:60:00Z", "2030-01-02T03:04:60Z", "2030-01-02T03:04:05+24:00", "2030-01-02T03:04:05+23:60", " 2030-01-02T03:04:05Z", "2030-13-01T00:00:00Z", "2030-00-10T00:00:00Z", "2030-04-31T00:00:00Z", "２030-01-02T03:04:05Z"}
	for _, s := range valid {
		if !ValidExpiry(StrOf(s)) {
			t.Fatalf("%q must be valid", s)
		}
	}
	for _, s := range invalid {
		if ValidExpiry(StrOf(s)) {
			t.Fatalf("%q must be invalid", s)
		}
	}
}

func TestPackOrderingAnchor(t *testing.T) {
	root := t.TempDir()
	names := []string{"\U0001F331.txt", "z.txt", "\U00010000.txt", "a/x.txt", "中.txt", "index.html", ".txt", "a.txt", "Ω.txt", "b.txt", "10.txt", "2.txt"}
	for _, n := range names {
		full := filepath.Join(root, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packed, err := PackDirectory(root, "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	// Hand-written expected order (not derived from the code under test).
	want := []string{"/10.txt", "/2.txt", "/a.txt", "/a/x.txt", "/b.txt", "/index.html", "/z.txt", "/Ω.txt", "/中.txt", "/.txt", "/\U00010000.txt", "/\U0001F331.txt"}
	if len(packed.Manifest.Files) != len(want) {
		t.Fatalf("expected %d files, got %d", len(want), len(packed.Manifest.Files))
	}
	for i, f := range packed.Manifest.Files {
		if !f.Path.Equal(StrOf(want[i])) {
			t.Fatalf("position %d: expected %q, got %q", i, want[i], string(f.Path))
		}
	}
}
