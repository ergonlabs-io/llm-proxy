# Documentation structure

The plan for the user-facing docs under `src/content/docs/`. It sets the
information architecture, the page contract every page follows, and the
writing rules. `astro.config.mjs` holds the sidebar; it must match this file.

## Audience and goals

Scope: the user docs cover only the `llmproxy` v0 config dialect
(`llm-proxy --config <file>`), the dialect that production runs. They never
document Envoy configuration, Envoy bootstrap files, xDS, or features that only
those reach. A feature the dialect does not expose is listed as not available
in `help/limitations`.

Readers are platform engineers who evaluate or run an LLM gateway, often
comparing llm-proxy with OpenRouter (a hosted router) or the LiteLLM proxy
(a self-hosted gateway). They need to answer three questions fast:

1. Can it route my traffic to my providers, with failover? (Getting started,
   Providers, API compatibility, Routing and reliability)
2. Can I control who spends what? (Access control, Limits and spend)
3. Can I run it in production and see what it does? (Observability,
   Administration, Operations)

Machine readers matter too. `starlight-llms-txt` builds `llms.txt` and
`llms-full.txt` from every page, and agents read pages one at a time. The page
contract below exists so that a single page, read alone, is correct and
complete.

## Sidebar

Status words: `existing` pages keep their slug and content; `revise` pages are
rewritten in place; `new` pages are written in this pass; `moved` slugs
redirect (Astro `redirects` in `astro.config.mjs`) to the page that now holds
their content. Slugs never change only for tidiness: inbound links matter more
than a neat URL.

### Getting started
| Slug | Status | Purpose |
|---|---|---|
| `getting-started/introduction` | revise | What llm-proxy is, what it is not, feature summary, how it differs from a hosted router and from LiteLLM. |
| `getting-started/quickstart` | existing | `init` → serve → first request → Admin UI, in about five minutes. |
| `getting-started/installation` | existing | `scripts/install.sh`, release archives, build from source, verify the install. |
| `getting-started/core-concepts` | new | Providers, models, routes, fallbacks, wire dialects, virtual keys, tenants, the request lifecycle. |
| `getting-started/connect-your-application` | existing | Point the OpenAI and Anthropic SDKs, curl, and agents at the proxy. |
| `getting-started/coming-from-litellm-or-openrouter` | new | Concept map from LiteLLM proxy and OpenRouter terms to llm-proxy terms; what has no equivalent. |

### Providers
| Slug | Status | Purpose |
|---|---|---|
| `providers/overview` | new | Provider type matrix: auth method, dialects, required fields, path rewrite; connections, DNS, TLS and concurrency ceilings. Holds the content of `providers-and-routing/providers-and-clusters`. |
| `providers/openai` | new | |
| `providers/anthropic` | new | |
| `providers/openrouter` | new | Includes the generated model example and the pricing catalog importer. |
| `providers/azure-openai` | new | |
| `providers/vertex-ai` | new | |
| `providers/amazon-bedrock` | new | |
| `providers/openai-compatible` | new | vLLM, Ollama, TGI, and hosted OpenAI-compatible APIs. |
| `providers-and-routing/providers-and-clusters` | moved → `providers/overview` | |

### API compatibility
| Slug | Status | Purpose |
|---|---|---|
| `api-compatibility/overview` | existing | Passthrough model, endpoints, model extraction, streaming, `/v1/models`, unmetered paths. |
| `api-compatibility/openai-chat-completions` | new | |
| `api-compatibility/openai-responses` | new | |
| `api-compatibility/anthropic-messages` | new | |
| `api-compatibility/realtime` | new | `realtime` WebSocket sessions. Holds the dialect content of `providers-and-routing/websocket-and-upgrades`. |
| `api-compatibility/errors` | new | Every proxy-generated error: status, body, cause, fix. |
| `providers-and-routing/websocket-and-upgrades` | moved → `api-compatibility/realtime` | |

SDK and client setup lives in `getting-started/connect-your-application`, not
in a separate `api-compatibility/sdks-and-clients` page: one page per task.

### Configuration
| Slug | Status | Purpose |
|---|---|---|
| `configuration/configuration-file` | existing | Guide to the file: layout, interpolation, validation. |
| `configuration/models-and-routes` | new | Model patterns, aliases, model rewrite, the `models` catalog, first-match order. |
| `configuration/strict-config-mode` | new | Strict parsing, dotted-path errors, load-time warnings. |

The field reference is generated (`configuration/reference`, listed under
Reference). It replaces the hand-written `reference/config-schema` page.

### Routing and reliability
| Slug | Status | Purpose |
|---|---|---|
| `providers-and-routing/failover-and-aggregates` | existing | |
| `providers-and-routing/load-balancing` | existing | Weights and session affinity across the providers of a model. |
| `providers-and-routing/auto-model` | existing | |
| `providers-and-routing/timeouts-and-retries` | existing | |

### Access control
| Slug | Status |
|---|---|
| `authentication/virtual-keys` | existing |
| `authentication/managing-secrets` | existing |
| `authentication/tenant-provider-credentials` | existing |
| `authentication/guardrails` | existing |
| `authentication/external-authorization` | moved → `help/limitations` (Envoy mode only) |

### Limits and spend
| Slug | Status |
|---|---|
| `limits-and-budgets/token-rate-limiting` | existing |
| `limits-and-budgets/pricing-and-cost-tracking` | new: rate cards, what is metered, cost in records |
| `limits-and-budgets/spend-policies` | existing: spend budgets on keys and tenants |
| `limits-and-budgets/current-usage` | existing |
| `limits-and-budgets/billing-ledger` | existing |
| `limits-and-budgets/chargeback-tags` | existing |

### Observability
| Slug | Status |
|---|---|
| `observability/overview` | existing |
| `observability/access-logs` | existing |
| `observability/metrics-and-stats` | existing |
| `observability/tracing` | new: OTLP distributed tracing |
| `observability/request-capture` | existing: the request records file |
| `observability/trace-export` | existing: request and response body export |

### Administration
| Slug | Status |
|---|---|
| `administration/admin-api` | new: holds the content of `observability/admin-endpoints` |
| `administration/admin-ui` | new |
| `observability/admin-endpoints` | moved → `administration/admin-api` |

### Operations
| Slug | Status |
|---|---|
| `operations/deployment` | new |
| `operations/kubernetes` | new |
| `operations/running-in-production` | existing |
| `operations/tls` | existing |
| `operations/config-reload` | existing |
| `operations/draining-and-shutdown` | existing |
| `operations/xds-conformance` | moved → `help/limitations` (contributor material, now in `internal-docs/envoy-mode/`) |

### Reference
| Slug | Status |
|---|---|
| `reference/cli` | revise |
| `configuration/reference` | existing, generated by `make config-reference` |
| `reference/response-flags` | new |
| `reference/metrics` | new |
| `reference/environment-variables` | new |
| `reference/glossary` | new |

### Help
| Slug | Status |
|---|---|
| `help/troubleshooting` | new |
| `help/faq` | new |
| `help/limitations` | new: everything not built, and everything only Envoy mode reaches, in one place |

## Page contract

Every page, new or revised, follows this contract.

### Frontmatter

`src/content.config.ts` defines the schema, and the build enforces it.

```yaml
---
title: Token rate limiting          # sentence case, 1-5 words
description: Limit tokens per minute per tenant and return 429 with x-ratelimit headers.
                                    # one sentence, <= 200 chars; Starlight and llms.txt use it
summary: >-                          # optional, 1-3 sentences; not rendered
  ...
lastUpdated: 2026-10-21
related:                             # docs slugs; a slug that names no page fails the build
  - limits-and-budgets/spend-policies
---
```

### Body shape

1. No `# H1` in the body. Starlight renders `title` as the H1.
2. Opening paragraph (2-4 sentences): what the feature does and when to use it.
3. An **At a glance** list for feature pages:
   - Default behavior when unset.
   - Failure mode (fails open or fails closed).
4. A minimal, complete example. YAML is a full file a reader can run with
   `--mode validate`, or is marked as a fragment in its code-block title.
5. Body sections with `##` / `###` headings that state the subject
   ("Revoking a key", not "Details").
6. Field tables: `| Field | Type | Default | Description |`.
7. A **Limitations** section: what the feature does not do. Link
   `help/limitations` for the full list.
8. Related pages go in the `related` frontmatter; the footer renders them.

### Writing rules

- Document what the code does at HEAD. Ground every behavioral claim in the
  schema, the IR, or a test. If a claim cannot be verified, leave it out and
  report it.
- Never document a planned feature as shipped. Name absent features plainly.
- Comparisons with OpenRouter and LiteLLM state only facts about llm-proxy
  plus widely known facts about the other product. No marketing claims.
- ASD-STE100 Simplified Technical English: short sentences, active voice, one
  instruction per step, consistent terms (see `reference/glossary`).
- Code blocks always carry a language: `yaml`, `bash`, `json`, `python`,
  `text`. Use `title="..."` for file names.
- Commands use ephemeral or documented ports (`53421` proxy, `53422` admin
  from the installer) and `curl --max-time`.
- Internal links are absolute and include the base path:
  `[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/)`. Relative
  links break when a page is opened without its trailing slash, and Starlight
  does not rewrite links in Markdown. Older pages still carry relative
  `../slug/` links; convert a link when you edit it.
- Never cite internal planning documents or work-package IDs in user docs.
