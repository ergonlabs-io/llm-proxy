# diffrig (WP-26)

Side-by-side differential test harness: runs llm-proxy and the pinned Envoy image
against shared scriptable upstreams, replays scenarios, and asserts equal behavior
(status, headers modulo allowlist, body, access-log fields, stats deltas,
upstream-observed attempt sequences).

Every scenario runs in BOTH config modes: static/file-watch and gRPC xDS
(PLAN.md Part 9.6 anti-rot rule).

Divergences are either failures or pinned with justification in
`docs/envoy-divergences.md`.
