# corpus

Versioned corpus of real-world Envoy configs and the scorecard tool that
classifies each as fully-supported / rejected-with-path / parse-error. The
scorecard percentage is the project's headline compatibility metric.

## Fixture sources

- `fixtures/local/` — small hand-written fixtures exercising specific
  outcome classes (one of each: fully-supported, rejected-with-path,
  parse-error).
- `fixtures/envoy-examples/` — real static bootstraps harvested verbatim
  from the `envoyproxy/envoy` repo's `configs/` tree at a pinned release
  tag. See `fixtures/envoy-examples/SOURCES.md` for the exact URL/ref per
  file. Not edited to pass the loader — a rejection here is a documented
  compat gap, not a bug to route around.

As of the last harvest (`v1.38.0`, 17 fixtures added), the combined
scorecard is **3/20 fixtures fully supported (15.0%)**. Run `cargo run -p
corpus` to regenerate `corpus-report.md` with the current numbers; treat
this percentage as a snapshot, not a target to game — most of the
"unsupported" results here name a real, if narrow, gap (typed extension
configs like access loggers, transport sockets, and listener filters we
haven't vendored/mapped yet), which is exactly what AGENTS.md invariant 1 is
for.
