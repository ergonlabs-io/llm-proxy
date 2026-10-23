---
title: Kubernetes and Helm
description: "Install llm-proxy on Kubernetes with the Helm chart: config from a ConfigMap, keys from a Secret, probes, drain on rollout, and a shared Redis store."
summary: How to install the llm-proxy Helm chart from GHCR, what the chart
  creates, how it wires readiness and the drain into a rolling update, how to
  share limits and spend across replicas with Redis, and the values you can
  set.
lastUpdated: 2026-10-22
related:
  - operations/deployment
  - operations/draining-and-shutdown
  - operations/running-in-production
  - authentication/managing-secrets
  - configuration/configuration-file
---

The release workflow publishes a container image and a Helm chart to the
GitHub container registry (GHCR). The chart runs llm-proxy as a Deployment (or a
StatefulSet) behind a Service. It reads your `--config` file from a
ConfigMap and your provider keys from a Secret. It sets the probes, the
preStop hook and the termination grace period so that a rolling update does
not fail a request that is in flight. The chart has no operator and no
custom resources.

:::caution
The image and the chart are published from v0.7.0.
:::

## At a glance

- **Image:** `ghcr.io/ergonlabs-io/llm-proxy:<version>`, for `linux/amd64`
  and `linux/arm64`. It runs as user `65532`, not root. It holds the release
  binary, the admin UI bundle and CA certificates. It has no shell.
- **Chart:** `oci://ghcr.io/ergonlabs-io/charts/llm-proxy`. The chart version
  is the release version, and the chart uses the image of the same version.
- **Requires:** Kubernetes 1.30 or later and Helm 3.8 or later (OCI
  registries).
- **Default when unset:** 2 replicas, a gradual drain of 300 seconds, a
  10-second preStop sleep, and no shared store. Each replica then enforces
  limits alone.
- **Failure mode:** a config that does not load stops the pod at start. The
  pod restarts and never becomes ready, so a rollout with a bad config stops
  before it replaces a working pod.

## Install the chart

Put your provider keys in a Secret. Each key of the Secret becomes an
environment variable in the pod. The config reads it with `${NAME}`.

```bash
kubectl create secret generic llm-proxy-env \
  --from-literal=OPENAI_API_KEY=sk-... \
  --from-literal=LLMPROXY_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

Write a values file. `config` is the llm-proxy config file in the `--config`
dialect, as YAML. It is required: the chart has no default config.

```yaml title="values.yaml"
existingSecret: llm-proxy-env
config:
  providers:
    openai:
      api_key: ${OPENAI_API_KEY}
  routes:
    - model: "*"
      provider: openai
```

Install the chart. Replace `0.7.0` with the release that you want:

```bash
helm install llm-proxy oci://ghcr.io/ergonlabs-io/charts/llm-proxy \
  --version 0.7.0 -f values.yaml --wait
```

Send a request through the Service from inside the cluster:

```bash
kubectl run curl --rm -it --restart=Never --image=curlimages/curl -- \
  curl --max-time 30 http://llm-proxy:8080/v1/chat/completions \
    -H 'content-type: application/json' \
    -d '{"model":"gpt-5-mini","messages":[{"role":"user","content":"hi"}]}'
```

If GHCR asks for credentials, the package is private. Log in with
`helm registry login ghcr.io` before you install, and set `imagePullSecrets`
to a Secret of type `kubernetes.io/dockerconfigjson` for `ghcr.io`.

## What the chart creates

| Object | Purpose |
|---|---|
| Deployment (or StatefulSet) | The proxy pods. |
| ConfigMap | The config file, mounted at `/etc/llm-proxy/llmproxy.yaml`. |
| Secret | Only when you set `secret.env`. Each key becomes an environment variable. |
| Service | Client traffic on port 8080. It does not expose the admin port. |
| PodDisruptionBudget | `maxUnavailable: 1`, so a node drain removes one pod at a time. |
| ServiceAccount | With no API token mounted. The proxy does not call the Kubernetes API. |

A change to the config or to `secret.env` changes a checksum annotation on
the pods, so `helm upgrade` rolls them. The chart does not use a `SIGHUP`
reload, because some settings need a restart. See
[Reload configuration](/docs/llm-proxy/operations/config-reload/).

### What the chart adds to your config

When your `config` leaves them out, the chart sets these keys:

| Key | Value |
|---|---|
| `version` | `0` |
| `listen` | `0.0.0.0:<ports.http>`, default `0.0.0.0:8080` |
| `admin` | `0.0.0.0:<ports.admin>`, default `0.0.0.0:9901` |

If you set `listen` or `admin`, use the ports in `ports.http` and
`ports.admin`. The probes and the Service use those ports.

To keep a config file exactly as you wrote it, with its comments, set
`configFile` to the file as a string. The chart then adds nothing. Set
`listen`, `admin` and, with `sharedStore`, `auth.store` yourself.

### Keep secrets out of the config

The ConfigMap is not secret. Write `${NAME}` in the config and supply `NAME`
from a Secret:

- `existingSecret`: a Secret that you manage. Every key becomes an environment
  variable. Use this in production.
- `secret.env`: a map of names to values. The chart writes a Secret from it.
  The values are then in your Helm values and in the Helm release record.

A `${NAME}` that is not set is a load error, and the pod does not start. For
secrets that the config reads from a file (`hmac_secret_file`,
`api_key_file`, TLS keys), mount a Secret with `extraVolumes` and
`extraVolumeMounts`. See
[Managing secrets](/docs/llm-proxy/authentication/managing-secrets/).

## Probes and the admin port

The admin server binds `0.0.0.0:9901` in the pod, because the kubelet probes
it on the pod IP.

| Probe | Request | Why |
|---|---|---|
| Readiness | `GET /ready` | `503` while the proxy starts and from the moment the drain starts. The pod leaves the Service endpoints. |
| Liveness | `GET /server_info` | `200` while the admin server runs, also during a drain. |

Liveness does not use `/ready`. `/ready` answers `503` for the whole drain
and after `POST /healthcheck/fail`. A liveness probe on `/ready` would kill
a pod that drains as intended.

The Service does not expose the admin port, but other pods in the cluster can
reach it on the pod IP. The read endpoints need no token. Admin writes need
`LLMPROXY_ADMIN_TOKEN`. Restrict the admin port with a NetworkPolicy if other
workloads share the cluster. To open the admin UI, forward the port:

```bash
kubectl port-forward deployment/llm-proxy 9901
```

Then open `http://127.0.0.1:9901/ui/`. See
[Admin UI](/docs/llm-proxy/administration/admin-ui/).

## Rolling updates without failed requests

A rollout surges one new pod and waits until it is ready
(`maxSurge: 1`, `maxUnavailable: 0`). Then Kubernetes stops an old pod in
this order:

1. The pod is marked for deletion. Kubernetes removes it from the Service
   endpoints. This takes some time to reach every node.
2. The preStop hook sleeps for `preStopSleepSeconds` (default 10). The proxy
   still accepts connections, so a client that the old endpoint list sends
   here is served.
3. Kubernetes sends `SIGTERM`. The proxy closes its listeners and starts the
   drain. Requests and streams in flight keep running for up to
   `drain.timeSeconds` (default 300). The process exits when no connection is
   left.
4. If the process still runs at `terminationGracePeriodSeconds`, the kubelet
   kills it.

The chart sets `terminationGracePeriodSeconds` to `preStopSleepSeconds +
drain.timeSeconds + 15` (default 325). If you set it lower than
`preStopSleepSeconds + drain.timeSeconds`, `helm install` fails, because the
kubelet would cut streams that the drain still allows.

`drain.strategy: gradual` (the default) spreads the closes of idle
keep-alive connections over the first quarter of the drain window, so your
clients do not all reconnect at once. See
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

Set `drain.timeSeconds` above your longest stream. A stream that runs past it
is cut. A long drain does not slow a rollout by itself: a pod with no open
connection exits at once.

The preStop hook uses the Kubernetes `sleep` action, because the image has
no shell. The action is on by default from Kubernetes 1.30.

## Share limits and spend across replicas

Without a shared store, each replica counts alone: 3 replicas admit up to 3
times each limit, and a key minted through the admin API exists on one
replica only. With `sharedStore`, the replicas share keys, tenant policy,
limits, spend and the rate card through Redis (`auth.store: shared`).

`sharedStore` needs an `auth` block in `config`, because `store` is part of
`auth`. The chart adds `auth.store.shared` to your config, mounts the Redis
URL from a Secret as a file, and passes `--service-node <pod name>` to each
pod.

```bash
kubectl create secret generic llm-proxy-redis \
  --from-literal=redis-url='redis://:password@redis-master:6379/0'
```

```yaml title="values.yaml (shared store)"
workload: StatefulSet
replicaCount: 3
existingSecret: llm-proxy-env
sharedStore:
  enabled: true
  existingSecret: llm-proxy-redis
config:
  auth:
    hmac_secret: ${LLMPROXY_AUTH_SECRET}
    keys: []
  providers:
    openai:
      api_key: ${OPENAI_API_KEY}
  routes:
    - model: "*"
      provider: openai
```

Use `workload: StatefulSet` with a shared store. The proxy uses the pod name
as its node ID. A StatefulSet pod keeps its name (`llm-proxy-0`,
`llm-proxy-1`) when it restarts. A Deployment pod gets a new name at every
rollout, and each new node ID leaves per-writer state in Redis. The chart
prints a note when you combine `sharedStore` with a Deployment.

Every pod of the release uses the same Redis namespace. It defaults to the
release's full name, so two releases can share one Redis. Set
`sharedStore.namespace` to choose it. For propagation delays and what happens
when Redis is not reachable, see
[Share state across replicas](/docs/llm-proxy/operations/running-in-production/).

## Values

| Value | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/ergonlabs-io/llm-proxy` | The image. |
| `image.tag` | the chart's `appVersion` | The image tag. |
| `workload` | `Deployment` | `Deployment` or `StatefulSet`. |
| `replicaCount` | `2` | Number of pods. |
| `config` | `{}` | The config file, as YAML. Required, unless you set `configFile`. |
| `configFile` | `""` | The config file, as a string. Replaces `config`. |
| `ports.http` | `8080` | Container port for client traffic. |
| `ports.admin` | `9901` | Container port for the admin server. |
| `existingSecret` | `""` | A Secret whose keys become environment variables. |
| `secret.env` | `{}` | Environment variables that the chart writes into a Secret. |
| `sharedStore.enabled` | `false` | Share state through Redis. |
| `sharedStore.existingSecret` | `""` | A Secret that holds the Redis URL. |
| `sharedStore.key` | `redis-url` | The key of the URL in that Secret. |
| `sharedStore.url` | `""` | The URL itself, when you do not use `existingSecret`. |
| `sharedStore.namespace` | the release's full name | The Redis key prefix. |
| `serviceNode` | `auto` | When to pass `--service-node <pod name>`: `auto` (with `sharedStore` or more than one replica), `always`, or `never`. |
| `drain.strategy` | `gradual` | `--drain-strategy`. |
| `drain.timeSeconds` | `300` | `--drain-time-s`. |
| `preStopSleepSeconds` | `10` | The preStop sleep. `0` removes the hook. |
| `terminationGracePeriodSeconds` | computed | At least `preStopSleepSeconds + drain.timeSeconds`. |
| `concurrency` | unset | `--concurrency`. Unset uses the CPUs that the container may use. |
| `logLevel` | `info` | `--log-level`. |
| `extraArgs`, `extraEnv` | `[]` | More arguments and environment variables. |
| `extraVolumes`, `extraVolumeMounts` | `[]` | More volumes, for example TLS files. |
| `service.type`, `service.port` | `ClusterIP`, `8080` | The Service. |
| `podDisruptionBudget.enabled` | `true` | Create the PodDisruptionBudget. |
| `podDisruptionBudget.maxUnavailable` | `1` | Its `maxUnavailable`. |
| `resources` | 250m CPU and 128Mi requested, 512Mi memory limit | Container resources. |

The chart's `values.yaml` lists every value with a comment, including the
probes, the security contexts and pod scheduling.

With more than one replica and no shared store, `serviceNode: auto` still
passes `--service-node`. When the config has an `auth` block, the proxy then
logs at start that limits and budgets apply per replica, so the gap is
visible. `helm install` prints the same warning.

## Limitations

- No operator and no custom resources. Configure the proxy through the
  chart's values.
- No Ingress or Gateway API object. Put your own in front of the Service.
- No NetworkPolicy for the admin port. Write one for your cluster.
- No HorizontalPodAutoscaler.
- The chart does not install Redis. Bring your own for `sharedStore`.
- `/ready` does not test providers. A provider outage does not take pods out
  of the Service.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
