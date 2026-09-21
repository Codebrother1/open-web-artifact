// Package owa is an independent, standard-library-only Go implementation of the
// portable Open Web Artifact (OWA) conformance semantics: canonical JSON and
// artifact identity, manifest and artifact-path validation, request-path
// resolution, directory packing, and the OCI image-layout boundaries exercised by
// the published corpus under docs/conformance/v0.2/.
//
// It is derived from docs/spec-v0.2.md, docs/conformance/README.md, docs/oci.md
// and the static corpus itself — not from the JavaScript reference packages. It
// is a conformance implementation, not a server, storage backend, CLI or SDK.
package owa

import "errors"

// Category is one of the 18 stable portable failure categories defined by the
// conformance guide. Internal messages are diagnostics only; the category is the
// portable contract.
type Category string

const (
	CatInvalidJSON             Category = "OWA_INVALID_JSON"
	CatInvalidJSONValue        Category = "OWA_INVALID_JSON_VALUE"
	CatInvalidManifest         Category = "OWA_INVALID_MANIFEST"
	CatUnsupportedSpecVersion  Category = "OWA_UNSUPPORTED_SPEC_VERSION"
	CatUnsupportedArtifactType Category = "OWA_UNSUPPORTED_ARTIFACT_TYPE"
	CatInvalidPath             Category = "OWA_INVALID_PATH"
	CatDuplicatePath           Category = "OWA_DUPLICATE_PATH"
	CatInvalidDigest           Category = "OWA_INVALID_DIGEST"
	CatInvalidSize             Category = "OWA_INVALID_SIZE"
	CatInvalidMediaType        Category = "OWA_INVALID_MEDIA_TYPE"
	CatMissingEntrypoint       Category = "OWA_MISSING_ENTRYPOINT"
	CatMissingSPAFallback      Category = "OWA_MISSING_SPA_FALLBACK"
	CatInvalidVisibility       Category = "OWA_INVALID_VISIBILITY"
	CatInvalidExpiry           Category = "OWA_INVALID_EXPIRY"
	CatInvalidAnnotations      Category = "OWA_INVALID_ANNOTATIONS"
	CatSymlink                 Category = "OWA_SYMLINK"
	CatContentDigestMismatch   Category = "OWA_CONTENT_DIGEST_MISMATCH"
	CatContentSizeMismatch     Category = "OWA_CONTENT_SIZE_MISMATCH"
)

// Error is a classified failure. Only Category is portable.
type Error struct {
	Category Category
	Message  string
}

func (e *Error) Error() string { return string(e.Category) + ": " + e.Message }

func fail(c Category, message string) error { return &Error{Category: c, Message: message} }

// CategoryOf reports the portable category of err, if it carries one.
// Transport-local errors (for example an OCI layout whose descriptors cannot be
// matched) have no category; the corpus never expects a category for them.
func CategoryOf(err error) (Category, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Category, true
	}
	return "", false
}
