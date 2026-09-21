# Go conformance implementation

An independent, standard-library-only Go implementation of the portable Open Web
Artifact semantics (specification v0.2 draft, manifest `specVersion`
`owa.dev/v1`), derived from the published documentation and the static corpus
under `docs/conformance/v0.2/` — not from the JavaScript reference packages.

```sh
go test ./... -count=1 -v
```

It is a conformance implementation only: no server, storage, CLI, SDK or
registry client. See [`docs/independent-implementation.md`](../../docs/independent-implementation.md)
for scope, independence rules, corpus coverage and the ambiguities it surfaced.
