# Security policy

llm-proxy sits in the request path and holds provider credentials. A defect here
can disclose API keys, leak one tenant's traffic to another, or take down a
service. Please report suspected vulnerabilities privately.

## Reporting a vulnerability

<!-- TODO(owner): name a real private reporting channel here, then link it from
     README.md and the docs site. Do not publish this file with a placeholder.
     If you use GitHub private vulnerability reporting (Security > Advisories >
     "Report a vulnerability"), check that it is enabled on the repository first. -->

**Contact: _not yet published_.** There is no private reporting channel yet.
Do not report a suspected vulnerability in a public issue. Wait until this
section names a private channel.

Please include: what you observed, how to reproduce it, the version or commit,
and the configuration involved (with secrets redacted). A proof of concept is
welcome but not required.

Expect an acknowledgement within a few working days. This is currently a
single-maintainer project, so please read that as a best effort rather than an
SLA.

## Scope

In scope — anything that lets a request or a configuration reach a state it
should not:

- Credential disclosure. **Sending one provider's API key to a different
  provider's endpoint is the highest-severity class here.** It has been found
  twice during development, and both times the cause was a per-provider value
  attached to the route rather than the cluster, so it followed the routing
  decision instead of the connection.
- Authentication or authorization bypass: reaching an upstream without a valid
  credential, or acting as another tenant.
- Rate-limit or quota bypass that lets one tenant consume another's budget.
- Cross-tenant leakage of request or response data, including through connection
  reuse. Upstream connections are keyed so that two clusters at the same address
  never share one; a way to defeat that keying is in scope.
- Request smuggling, header injection, or response splitting.
- TLS verification flaws: accepting a certificate that should be rejected,
  ignoring SNI or hostname verification, or silently downgrading to plaintext.
- Denial of service reachable by a single well-formed request, or an
  unauthenticated remote crash.

Out of scope:

- Anything requiring control of the configuration file. Configuration is trusted
  input; an operator who can edit it already controls the proxy.
- Findings against the admin endpoint when it is bound to a public interface.
  It is documented as loopback-only, exposes `/config_dump`, and is unauthenticated.
- Load-based resource exhaustion that any proxy exhibits under sufficient traffic.
- Vulnerabilities in an upstream provider's own API.
- Dependency advisories with no reachable path in this codebase — though these
  are welcome as ordinary issues.

## Known gaps

These are documented weaknesses, not vulnerabilities. They are listed so nobody
spends time reporting them, and so operators can judge the risk themselves:

- **Authorization covers models only.** With an `auth:` block, an authenticated
  tenant that has no stored model policy is refused with `403` (the default,
  `auth.enforce.tenants_without_policy: deny`). There is no per-tenant provider
  authorization: a tenant that may use a model may use every provider that
  serves it. The starter config that `llm-proxy init` writes sets
  `tenants_without_policy: allow`, so its key can use every model. Remove that
  setting before you issue keys to other people.
- **Keys in the config file change only on restart.** `auth.keys`, the HMAC
  secret, the auth store, the credential key ring and the policy poll interval
  are fixed when the proxy starts. A `SIGHUP` reload that changes one of them
  is refused whole and logged at `error`, so setting `revoked: true` on a
  configured key takes effect only after a restart. To revoke without a
  restart, use the admin API: `DELETE /keys/{id}` revokes an API-minted key,
  and `DELETE /tenants/{id}` revokes every key of a tenant, including
  configured keys. Other replicas see a revocation at their next policy poll
  (48 to 60 seconds). A request that was admitted before the revocation is not
  stopped.
- **File-sourced credentials and certificates are not watched.** Nothing
  re-reads a file when it changes on disk; see
  [Config reload](docs/site/src/content/docs/operations/config-reload.md) for
  which files a `SIGHUP` re-reads.
- Sending a request with no recognized credential is refused, but there is no
  rate limiting on authentication attempts themselves.
- **A token budget is not charged if usage cannot be read from the response.**
  On a route with a budget configured, if the provider's response usage
  cannot be extracted (most commonly a usage-filter `dialect` mismatch for
  that provider), the request is allowed and nothing is charged against the
  budget — the proxy fails open rather than refusing traffic on a metering
  hiccup. This now warns (`token_limit: the token budget for this request was
  NOT enforced...`, at most once per budget key per minute) so the gap is
  visible in logs; it does not deny the request or retroactively correct the
  budget.

## Supported versions

The 1.x releases follow the [stability policy](https://ergonlabs.io/docs/llm-proxy/reference/stability/).
Fixes land on `main` and ship in the next release;
there are no backports to earlier tags.
