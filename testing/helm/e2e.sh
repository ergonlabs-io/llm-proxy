#!/usr/bin/env bash
# Chart test on a local cluster (`make helm-e2e`).
#
# 1. Creates a throwaway cluster with kind, or with minikube when kind is not
#    installed, and builds and loads a local image (build-image.sh).
# 2. Installs the chart (values-e2e.yaml) in front of mock-upstream.
# 3. Sends one request through the Service and expects 200.
# 4. Rolls the Deployment while a client pod (client.sh) holds long streams
#    open on the old pods and sends a short request every 200 ms. Every
#    request must get 200 and a complete stream, and the long streams must
#    end after the rollout finished, so they outlived the pods that served
#    them.
#
# It uses its own kubeconfig file, so it never reads or changes your current
# kubectl context.
#
# Env: E2E_CLUSTER=kind|minikube  force the cluster tool
#      E2E_KEEP=1                 keep the cluster afterwards
#      E2E_SKIP_BUILD=1           reuse the images from a previous run
#      E2E_SET="k=v,..."          extra `helm --set` values (for example to
#                                 check that a short drain makes it fail)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
name=llm-proxy-helm-e2e
release=lp
service="$release-llm-proxy"
image=llm-proxy:helm-e2e
mock_image=llm-proxy-mock-upstream:helm-e2e
curl_image=curlimages/curl:8.11.1
slow=4
duration=45

for tool in docker helm kubectl; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
cluster="${E2E_CLUSTER:-}"
if [ -z "$cluster" ]; then
  if command -v kind >/dev/null; then cluster=kind
  elif command -v minikube >/dev/null; then cluster=minikube
  else echo "need kind or minikube" >&2; exit 1
  fi
fi

work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "==> FAILED; cluster state:"
    kubectl get pods -o wide 2>/dev/null || true
    kubectl logs -l app.kubernetes.io/instance=$release --tail=30 --prefix 2>/dev/null || true
  fi
  if [ "${E2E_KEEP:-}" = 1 ]; then
    echo "==> keeping cluster $name (KUBECONFIG=$KUBECONFIG)"
  else
    echo "==> deleting cluster $name"
    case "$cluster" in
      kind) kind delete cluster --name "$name" >/dev/null 2>&1 || true ;;
      minikube) minikube delete -p "$name" >/dev/null 2>&1 || true ;;
    esac
    command rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

if [ "${E2E_SKIP_BUILD:-}" != 1 ]; then
  "$here/build-image.sh" "$image"
fi
docker image inspect "$curl_image" >/dev/null 2>&1 || docker pull -q "$curl_image"

echo "==> creating $cluster cluster $name"
case "$cluster" in
  kind)
    kind create cluster --name "$name" --kubeconfig "$KUBECONFIG" --wait 120s
    for img in "$image" "$mock_image" "$curl_image"; do kind load docker-image --name "$name" "$img"; done
    ;;
  minikube)
    minikube start -p "$name" --driver=docker --wait=all
    for img in "$image" "$mock_image" "$curl_image"; do minikube -p "$name" image load "$img"; done
    ;;
  *) echo "E2E_CLUSTER must be kind or minikube" >&2; exit 1 ;;
esac

echo "==> deploying mock-upstream"
kubectl apply -f "$here/mock-upstream.yaml"
kubectl rollout status deployment/mock-upstream --timeout=120s

echo "==> installing the chart"
helm install "$release" "$repo/deploy/helm/llm-proxy" -f "$here/values-e2e.yaml" \
  ${E2E_SET:+--set "$E2E_SET"} --wait --timeout 180s

echo "==> one request through the Service"
code="$(kubectl run smoke --rm -i --restart=Never --image="$curl_image" --image-pull-policy=Never --quiet -- \
  curl -sS --max-time 30 -o /dev/null -w '%{http_code}' "http://$service:8080/v1/chat/completions" \
  -H 'content-type: application/json' -d '{"model":"mock-fast","messages":[{"role":"user","content":"hi"}]}')"
echo "status $code"
[ "$code" = 200 ] || { echo "expected 200 through the Service, got $code" >&2; exit 1; }

echo "==> rolling the Deployment under load"
old_pods="$(kubectl get pods -l app.kubernetes.io/instance=$release -o name | sort)"
kubectl create configmap e2e-client --from-file=client.sh="$here/client.sh"
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: client
spec:
  restartPolicy: Never
  containers:
    - name: client
      image: $curl_image
      imagePullPolicy: Never
      command: ["sh", "/s/client.sh"]
      env:
        - {name: SERVICE, value: "$service"}
        - {name: PORT, value: "8080"}
        - {name: SLOW, value: "$slow"}
        - {name: DURATION, value: "$duration"}
      volumeMounts: [{name: s, mountPath: /s}]
  volumes:
    - name: s
      configMap: {name: e2e-client}
YAML
kubectl wait --for=condition=Ready pod/client --timeout=60s
# Let the long streams reach the old pods before they are replaced.
sleep 3
kubectl rollout restart "deployment/$service"
kubectl rollout status "deployment/$service" --timeout=300s
rolled_at="$(date +%s)"
# `rollout status` returns once the new pods are ready; the old ones are then
# terminating or gone. Wait until none of them is left.
for pod in $old_pods; do kubectl wait --for=delete "$pod" --timeout=180s || true; done
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/client --timeout=180s
log="$work/client.log"
kubectl logs client >"$log"

echo "==> checking results"
fast_total="$(grep -c '^fast ' "$log" || true)"
slow_total="$(grep -c '^slow ' "$log" || true)"
bad="$(grep -E '^(fast|slow) ' "$log" | grep -v -E ' 200 0 yes [0-9]+$' || true)"
slow_last="$(awk '$1 == "slow" { if ($5 > m) m = $5 } END { print m + 0 }' "$log")"
echo "fast requests: $fast_total, slow streams: $slow_total, rollout done at $rolled_at, last slow stream ended at $slow_last"
fail=0
if [ -n "$bad" ]; then
  echo "requests that failed:" >&2
  echo "$bad" >&2
  grep '^  curl:' "$log" | sort | uniq -c >&2 || true
  fail=1
fi
[ "$slow_total" -eq "$slow" ] || { echo "expected $slow slow streams, saw $slow_total" >&2; fail=1; }
[ "$fast_total" -ge 50 ] || { echo "expected at least 50 short requests, saw $fast_total" >&2; fail=1; }
# A stream that ended before the rollout finished proves nothing about the
# drain.
[ "$slow_last" -gt "$rolled_at" ] || { echo "the slow streams ended before the rollout finished; the test did not hold a request across a pod's termination" >&2; fail=1; }
[ "$fail" -eq 0 ] || exit 1
echo "==> PASS: 200 through the Service, and no failed request across the rollout"
