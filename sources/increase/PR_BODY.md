## Summary

- Replaces generated Increase read and discover fixtures with inert provider-shaped payloads from the official Increase OpenAPI examples.
- Adds every-family replay coverage, provider-unavailable behavior coverage, and runtime deploy entries for each Increase family.
- Updates Increase coverage notes, control references, and documented unsupported incremental watermark behavior.

## Validation

- `go test ./sources/increase -count=1`
- `make catalog-check sourcegen-check`
- `go run ./tools/sourcefidelity -json-out /tmp/increase-fidelity.json`
