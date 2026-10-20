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

# model_wildcard and route_model_glob: pattern, 0xFF, model name. Patterns are
# every quoted `model:` the dialect examples and tests use; names are a few
# models those patterns are written for.
patterns=$(grep -ho 'model: *"[^"]*"' "$root"/examples/*.yaml \
    "$root"/crates/proxy-simple-config/tests/*.rs | sed 's/^model: *"//; s/"$//' | sort -u)
names=(gpt-4o gpt-5-mini claude-sonnet-4-5 a.b local-llama "")
for target in model_wildcard route_model_glob; do
    mkdir -p "$corpus/$target"
    i=0
    while IFS= read -r pattern; do
        for name in "${names[@]}"; do
            { printf '%s' "$pattern"; printf '\377'; printf '%s' "$name"; } \
                > "$corpus/$target/seed-$i"
            i=$((i + 1))
        done
    done <<< "$patterns"
done

# vhost_domain: authority, then one virtual host per line (domains split by
# `,`), using the domain shapes the route-table tests configure.
mkdir -p "$corpus/vhost_domain"
printf 'api.example.com:8443\n*.example.com\napi.example.com\nexample.*\n*' \
    > "$corpus/vhost_domain/seed-0"
printf 'EXAMPLE.com\nexample.com,a.example.com\n*.api.example.com\nb.example.com' \
    > "$corpus/vhost_domain/seed-1"
printf '[::1]:8080\n*\n[::1]' > "$corpus/vhost_domain/seed-2"

# access_log_format: every format string the formatter's unit tests parse.
mkdir -p "$corpus/access_log_format"
i=0
grep -o 'parse("[^"]*")' "$root/crates/proxy-observability/src/access_log.rs" \
    | sed 's/^parse("//; s/")$//' | sort -u | while IFS= read -r format; do
    printf '%s' "$format" > "$corpus/access_log_format/seed-$i"
    i=$((i + 1))
done

# admin_body: byte 0 = endpoint (0 mint, 1 tenant, 2 key budget, 3 trace
# export, 4 policy, 5 limits), then the body. Bodies are the JSON literals
# the admin server tests send, routed by their first field.
mkdir -p "$corpus/admin_body"
i=0
grep -ho 'r#"{[^#{]*}*"#' "$root"/crates/proxy-admin/src/server/tests.rs \
    "$root"/crates/proxy-admin/src/server/tests/*.rs | sed 's/^r#"//; s/"#$//' | sort -u \
    | while IFS= read -r body; do
    case "$body" in
        *'"key_id"'*) e='\000' ;;
        *'"tenant"'*) e='\001' ;;
        *'"budget"'*) e='\002' ;;
        *'"enabled"'*) e='\003' ;;
        *'"access"'*) e='\004' ;;
        *'"limits"'*) e='\005' ;;
        *) continue ;;
    esac
    { printf "$e"; printf '%s' "$body"; } > "$corpus/admin_body/seed-$i"
    i=$((i + 1))
done

# virtual_key_auth: stored key suffix, 0xFF, Authorization value.
mkdir -p "$corpus/virtual_key_auth"
printf 'abc123\377Bearer llmp_abc123' > "$corpus/virtual_key_auth/seed-0"
printf 'abc123\377Bearer llmp_revoked-key' > "$corpus/virtual_key_auth/seed-1"
printf 'abc123\377Bearer eyJhbGciOi.x.y' > "$corpus/virtual_key_auth/seed-2"
printf 'abc123\377bearer llmp_abc123' > "$corpus/virtual_key_auth/seed-3"

# router_body: flags, cap, deny mask, strip mask, rewrite pattern, then a
# body: the body_prefix_scan bodies above plus the router tests' literals.
mkdir -p "$corpus/router_body"
i=0
{
    printf '%s\n' "${bodies[@]}"
    grep -o 'br#"{[^#]*}"#' "$root/crates/proxy-http/src/router.rs" | sed 's/^br#"//; s/"#$//'
} | sort -u | while IFS= read -r body; do
    for header in '\107\144\003\004\001' '\001\000\000\000\004' '\306\012\001\002\000'; do
        { printf "$header"; printf '%s' "$body"; } > "$corpus/router_body/seed-$i"
        i=$((i + 1))
    done
done

# media_scan: byte 0 = chunk size, then an image response body (JSON or SSE).
mkdir -p "$corpus/media_scan"
printf '\007{"created":1,"data":[{"b64_json":"QUJD","revised_prompt":"a \\"cat\\""}],"size":"1024x1024","quality":"high","usage":{"input_tokens":50,"input_tokens_details":{"text_tokens":40,"image_tokens":10},"output_tokens":4160,"total_tokens":4210}}' > "$corpus/media_scan/seed-json"
printf '\003{"data":["a",{"url":"u"},null],"\\u0073ize":"512x512"}' > "$corpus/media_scan/seed-escaped"
printf '\005event: image_generation.partial_image\ndata: {"type":"image_generation.partial_image","b64_json":"QQ"}\n\nevent: image_generation.completed\r\ndata: {"type":"image_generation.completed","b64_json":"QUJD","size":"1024x1536","quality":"medium","usage":{"input_tokens":7,"output_tokens":100}}\r\n\r\n' > "$corpus/media_scan/seed-sse"
