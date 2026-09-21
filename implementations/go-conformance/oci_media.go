package owa

// Constants of the OWA manifest and of its OCI image-layout representation
// (docs/oci.md "The representation").
const (
	SpecVersion        = "owa.dev/v1"
	OWAMediaType       = "application/vnd.openwebartifact.site.v1+json"
	OCIImageManifest   = "application/vnd.oci.image.manifest.v1+json"
	OCIImageIndex      = "application/vnd.oci.image.index.v1+json"
	OCILayoutVersion   = "1.0.0"
	OCIFallbackMedia   = "application/octet-stream"
	AnnotationPath     = "dev.openwebartifact.path"
	AnnotationTitle    = "org.opencontainers.image.title"
	AnnotationArtifact = "dev.openwebartifact.artifact.digest"
	AnnotationRefName  = "org.opencontainers.image.ref.name"
)

// LayerMediaType maps an OWA file.mediaType (an arbitrary nonempty string that
// may carry parameters) to the OCI layer DESCRIPTOR media type (docs/oci.md
// "Layer descriptor media types"): take the value up to the first `;`, trim
// ASCII SP/HTAB, use it verbatim when it satisfies the OCI image-spec
// descriptor grammar `type/subtype` with each part matching
// [A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}; otherwise application/octet-stream.
// The full OWA value stays only in the canonical config manifest.
func LayerMediaType(full string) string {
	candidate := full
	for i := 0; i < len(full); i++ {
		if full[i] == ';' {
			candidate = full[:i]
			break
		}
	}
	candidate = trimSPHTAB(candidate)
	if isDescriptorMediaType(candidate) {
		return candidate
	}
	return OCIFallbackMedia
}

func trimSPHTAB(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func isDescriptorMediaType(s string) bool {
	slash := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			if slash != -1 {
				return false
			}
			slash = i
		}
	}
	if slash == -1 {
		return false
	}
	return isRestrictedName(s[:slash]) && isRestrictedName(s[slash+1:])
}

// isRestrictedName: first character alphanumeric, then up to 126 characters
// from [A-Za-z0-9!#$&^_.+-]; total length 1..127.
func isRestrictedName(s string) bool {
	if len(s) < 1 || len(s) > 127 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !alnum {
				return false
			}
			continue
		}
		if alnum {
			continue
		}
		switch c {
		case '!', '#', '$', '&', '^', '_', '.', '+', '-':
		default:
			return false
		}
	}
	return true
}
