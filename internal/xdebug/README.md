# Vendored golang.org/x/debug analyzer

Copied from `golang.org/x/debug@v0.0.0-20261009152145-82c9183adedd`
(`internal/core`, `internal/gocore`, `dwtest`, `third_party/delve`) because
`internal/gocore` cannot be imported from another module. BSD license: `LICENSE`,
`delve/LICENSE`.

Local patches:

- `gocore/gcmask.go` + call sites in `process.go`/`type.go`: support
  `TFlagGCMaskOnDemand` (Go 1.24+). `GCData` is dereferenced once to reach the
  bitmap. A nil slot or unreadable mask adds a diagnostic and no pointer edges;
  the slot is never scanned as a bitmap. Unpatched viewcore reads past the slot
  and panics on unmapped memory (e.g. Go 1.27.2 core at `0x37d1000`).
- `gocore/process.go` + `gcmask.go`: record malloc-header / `span.largeType` types per object; `AllocType` exposes them for naming untyped objects.
- `gocore/allocsite.go` + specials loop in `process.go`: record `_KindSpecialProfile` specials; `AllocStack` reads the bucket stack, `MemProfileRate` reads the runtime variable.
- `gocore/process.go`: backtrace warnings go to `Diagnostics()` instead of stdout.

To update: re-copy, rewrite import paths to this module, re-apply the patches,
run `go test ./internal/objects/`.
