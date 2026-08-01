# ADR 0002 — Config pipeline: prost-reflect proto3-JSON against Envoy descriptors

**Status:** accepted (scaffold)

## Decision

Bootstrap and xDS resources share one pipeline:

```
YAML/JSON --(serde)--> serde_json::Value
  --(prost-reflect proto3-JSON deserialize against the vendored Envoy
     FileDescriptorSet, deny_unknown_fields in strict mode)--> typed prost messages
  --(PGV-subset validation)--> validated protos
  --(TryFrom conversions, exhaustive per message)--> internal IR (ConfigSnapshot)
```

The data plane consumes only the IR; protobuf types never escape `proxy-config` /
`proxy-xds` (ground rule #3).

## Why

- Hand-written serde structs mirroring Envoy YAML would drift forever;
  prost-reflect gives the exact proto3 JSON mapping (durations, `Any` by type URL,
  wrappers, oneofs) for free from the pinned descriptors.
- Unknown-field detection is what makes strict mode (ground rule #2: never
  silently ignore config) enforceable.
- One pipeline means static config and xDS NACKs produce identical, field-path-
  precise errors.

## Consequences

- `proxy-api` must embed the `FileDescriptorSet` (WP-02).
- IR conversion must be exhaustive per proto message so proto upgrades fail loudly
  (WP-05 checklists).
