# Security policy

llm-proxy sits in the request path and holds provider credentials. A defect here
can disclose API keys, leak one tenant's traffic to another, or take down a
service. Please report suspected vulnerabilities privately.

## Reporting a vulnerability

<!-- TODO before publishing: replace with a real contact. GitHub private
     vulnerability reporting (Security > Advisories > "Report a vulnerability")
     is the lowest-friction option and needs no published address. -->

**Contact: _not yet published_.** Until this line names a real destination,
there is no private channel — please do not file suspected vulnerabilities in
public issues in the meantime; wait, or contact the maintainer directly.

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

- **Credential and certificate files are read once at startup.** There is no
  file watching. A rotated key or a renewed certificate takes effect only after
  a restart or a SIGHUP config reload.
- **There is no credential revocation store.** Virtual keys come from
  configuration, so revoking one means changing the config and reloading.
- **Authorization defaults open.** An authenticated tenant with no configured
  policy may use every model and provider. Authentication fails closed;
  authorization does not.
- Sending a request with no recognized credential is refused, but there is no
  rate limiting on authentication attempts themselves.

## Supported versions

Pre-1.0 and moving quickly. Fixes land on `main` and ship in the next release;
there are no backports to earlier tags.
