#!/usr/bin/env bash
# Build each fuzz target's starting corpus from fixtures the test suites
# already use, so no seed file is duplicated into the tree. Idempotent:
# rerunning only refreshes the seed-* files and keeps what the fuzzer found.
#
# Usage: fuzz/seed.sh   (run from the repository root)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
corpus="$root/fuzz/corpus"
traces="$root/crates/proxy-observability/tests/fixtures/traces"

# usage_extract: byte 0 = dialect (0 OpenAI, 1 Anthropic, 2 Responses),
# byte 1 = chunk size, then the body.
mkdir -p "$corpus/usage_extract"
for f in "$traces"/*.sse "$traces"/*.json; do
    name=$(basename "$f")
    case "$name" in
        openai_chat*) d='\000' ;;
        anthropic*) d='\001' ;;
        openai_responses*) d='\002' ;;
        *) continue ;;
    esac
    { printf "$d"'\007'; cat "$f"; } > "$corpus/usage_extract/seed-$name"
done

# body_prefix_scan: byte 0 = chunk size, byte 1 = cap (0 = default), then
# the request body.
mkdir -p "$corpus/body_prefix_scan"
bodies=(
    '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}'
    '{"model":"m","stream":true}'
    '{"model":"expensive"}'
    '{"model":"a","model":1}'
    '{"stream":true,"stream_options":{"include_usage":false},"model":"m"}'
    '  {"messages":[{"content":"a \"quoted\" ] } string"}],"model":"x","stream":true}'
    '{"model":"m","max_tokens":10,"stream":false}'
)
i=0
for body in "${bodies[@]}"; do
    printf '\005\000%s' "$body" > "$corpus/body_prefix_scan/seed-$i"
    i=$((i + 1))
done

# dialect_config: the shipped dialect examples, plus a comment-masking case.
# The generated OpenRouter catalog (~500 KB) is skipped: an input that large
# drops the fuzzer to a few executions per second and adds no new syntax.
mkdir -p "$corpus/dialect_config"
for f in "$root"/examples/llmproxy*.yaml; do
    [ "$(wc -c < "$f")" -le 65536 ] || continue
    cp "$f" "$corpus/dialect_config/seed-$(basename "$f")"
done
printf 'version: 0\n# api_key: ${UNSET_KEY}\nnote: "a # not a comment ${X}"\nblock: |\n  # ${UNSET_IN_BLOCK}\n' \
    > "$corpus/dialect_config/seed-comment-mask.yaml"
