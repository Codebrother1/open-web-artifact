# Changelog

## 0.2.0 - 2026-09-20

- add deterministic canonical manifest encoding and published test vector
- add two-phase HTTP publishing: plan, direct blob upload, commit
- add dependency-free S3 Signature V4 backend with path and virtual-host addressing
- verify S3 presigning against Amazon's published SigV4 test vector
- add OCI image-layout export/import compatible with ORAS workflows
- add manifest JSON Schema
- harden artifact path validation and reject symlinks while packing
- expand conformance suite and remote end-to-end coverage

## 0.1.0 - 2026-09-20

- initial content-addressed filesystem prototype
- immutable releases, deduplication, activation, rollback, gateway, and CLI
