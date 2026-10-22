#!/usr/bin/env bash
# `make helm-check`, also run by CI: helm lint and helm template for every
# values file in deploy/helm/llm-proxy/ci, and the template-time guards that
# must refuse a bad value. The defaults alone do not render: `config` is
# required.
#
# With LLM_PROXY_BIN set, it also loads each rendered config file with
# `llm-proxy --mode validate`, so a chart default the dialect rejects fails
# here rather than in a pod. Shared-store files are skipped: they name a
# Redis URL file that exists only in the pod.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
chart="$repo/deploy/helm/llm-proxy"
work="$(mktemp -d)"
trap 'command rm -rf "$work"' EXIT

for values in "$chart"/ci/*.yaml "$repo/testing/helm/values-e2e.yaml"; do
  echo "==> $values"
  helm lint --strict "$chart" -f "$values"
  helm template check "$chart" -f "$values" >"$work/out.yaml"
  if [ -n "${LLM_PROXY_BIN:-}" ]; then
    helm template check "$chart" -f "$values" -s templates/configmap.yaml \
      | python3 -c 'import sys, yaml; print(yaml.safe_load(sys.stdin)["data"]["llmproxy.yaml"])' >"$work/llmproxy.yaml"
    if grep -q 'url_file: /var/run/llm-proxy/redis/' "$work/llmproxy.yaml"; then
      echo "skip validate (shared store)"
    else
      OPENAI_API_KEY=x LLMPROXY_AUTH_SECRET=0123456789abcdef0123456789abcdef \
        "$LLM_PROXY_BIN" --config "$work/llmproxy.yaml" --mode validate
    fi
  fi
done

# Each of these must fail to render, with the given text in the error.
refuse() {
  local want="$1"; shift
  if out="$(helm template check "$chart" "$@" 2>&1)"; then
    echo "expected helm template $* to fail" >&2; exit 1
  fi
  grep -qF "$want" <<<"$out" || { echo "helm template $* failed without '$want':" >&2; echo "$out" >&2; exit 1; }
  echo "refused as expected: $*"
}
ok="$chart/ci/openai-values.yaml"
refuse "set config (the llm-proxy --config file, as YAML) or configFile"
refuse "must be at least preStopSleepSeconds + drain.timeSeconds" -f "$ok" --set terminationGracePeriodSeconds=100
refuse "needs an \`auth\` block" -f "$ok" --set sharedStore.enabled=true --set sharedStore.url=redis://r:6379
refuse "needs sharedStore.existingSecret or sharedStore.url" -f "$chart/ci/shared-store-values.yaml" --set sharedStore.existingSecret=
refuse "workload must be Deployment or StatefulSet" -f "$ok" --set workload=DaemonSet
refuse "drain.strategy must be immediate or gradual" -f "$ok" --set drain.strategy=slow
refuse "serviceNode must be auto, always or never" -f "$ok" --set serviceNode=sometimes
echo "==> helm chart checks passed"
