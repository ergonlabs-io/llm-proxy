# WP-50 increment 2 — downstream authentication: design brief

**Status:** design agreed with the repo owner 2026-08-08. Increment 2a (virtual
keys, in-memory) is the buildable slice; everything else here is the seam it
must not foreclose.

## The hole

There is **no application-level authentication** today. The only downstream
identity is transport-level mTLS (`require_client_certificate` in the IR),
which proves a client holds a certificate and tells you nothing about *which
tenant* they are.

Two consequences, both load-bearing:

1. **Unless mTLS is on, the proxy is a credential-laundering open relay.** It
   holds real provider keys and injects them upstream (`ClusterConfig::
   request_headers_to_add`). Anyone who reaches the listener spends the
   operator's provider budget, under the operator's account.

2. **The token rate limit is bypassable by construction.**
   `token_limit_filter.rs` buckets on
   `hash_credential(<client-supplied Authorization header>)`. Nothing verifies
   that header, so a caller who wants more quota changes it and gets a fresh
   bucket. This is not a defect in WP-34 — it does exactly what it says — but
   it means **v0.1.0's "a token-based rate limit is enforced" clause cannot be
   honestly verified until callers have identities the proxy assigns.** Auth is
   not a follow-on feature here; it is on the critical path to the release.

## Shape

### The authenticator is a trait; virtual keys are one implementation

The owner intends OIDC later. So the filter must not be "the virtual key
filter" — it is an authentication filter that consults one or more
authenticators and produces a `Principal`.

```rust
/// Resolves a request to a caller identity, or refuses it.
trait Authenticator: Send + Sync {
    fn authenticate(&self, headers: &RequestHeaders) -> AuthOutcome;
}

enum AuthOutcome {
    Authenticated(Principal),
    /// No credential of this authenticator's kind was presented -- try the
    /// next one. Distinct from Rejected: absence is not failure.
    NoCredential,
    /// A credential of this kind WAS presented and is bad. Terminal: do not
    /// fall through to another authenticator, or a caller could probe each
    /// mechanism in turn.
    Rejected(AuthError),
}
```

The `NoCredential` / `Rejected` split is the load-bearing part. Collapsing them
into one "failed" case makes a chain of authenticators into an oracle: present
a malformed JWT, fall through to the key authenticator, learn something. A bad
credential of a known kind terminates.

**OIDC fits this without reshaping it**, which is the test of the seam: JWKS
fetching is async and off the hot path (an `ArcSwap` snapshot, same as
everything else here); token *validation* against a cached JWKS is CPU-bound
and synchronous. So a `JwtAuthenticator` is a second `impl Authenticator` and
nothing above it changes.

### `Principal` carries policy, not just an identity

Account policies are coming, so the authenticated value must be able to carry
them from the start:

```rust
struct Principal {
    tenant: TenantId,
    /// WHICH credential authenticated. Separate from `tenant` because
    /// revoking one leaked key must not revoke the team, and because audit
    /// needs to name the key, not the account.
    key_id: KeyId,
    /// Model allow-lists, budgets, quotas. An Arc so the hot path clones a
    /// pointer, and so a policy change is a snapshot swap rather than a
    /// per-request lookup.
    policy: Arc<TenantPolicy>,
}
```

`TenantPolicy` starts nearly empty (increment 2a needs no fields). It exists so
that adding the first policy is not a signature change through every call site.

### Filter ordering, including one non-obvious constraint

```
authn                  -> Principal on the request context, or 401
  |
body peek (WP-45)      -> the model name lives in the request BODY
  |
authz: model allow-list-> CANNOT run at header time; needs the peek
  |
token limiter          -> keys on Principal.tenant, NOT on a client header
  |
router -> cluster injects the real provider credential
```

**"May this tenant use `gpt-5`?" cannot be answered in `decode_headers`,**
because the model is in the body. WP-45 already built the bounded body-peek
pipeline, so the seam exists — but model-scoped authz is structurally a
post-peek filter, and anyone designing it as a header filter will hit a wall.

Re-keying the limiter onto `Principal.tenant` is what converts the rate limit
from advisory into enforceable. It is a small change and it is the point of
increment 2a.

## Decisions that are easy to get wrong

### SHA-256 is correct here; Argon2/bcrypt would be a self-inflicted DoS

Virtual keys are **high-entropy values the proxy generates**, not user-chosen
passwords. The reason password hashing is deliberately slow is to survive low
entropy; that reasoning does not transfer. A per-request Argon2 on the hot path
is a denial-of-service the operator inflicts on themselves.

Use a **keyed** hash (HMAC-SHA-256 with an operator secret) so that read access
to the store does not permit offline precomputation, and compare in constant
time.

**Do NOT reuse `token_limit_filter::hash_credential`.** It is FNV-1a, chosen
for stability across processes on a *non-adversarial* bucket key. It offers
neither preimage resistance nor constant-time comparison. Both functions are
spelled "hash a credential", which is exactly why this keeps needing saying.

### Key format

Keys carry a printable prefix (`llmp_`) so they are greppable in incident
response, revocable by prefix scan, and distinguishable from a provider key
pasted into the wrong field — which is a real support case, and one the proxy
can detect and name.

### Fail closed, and what that means precisely

ADR-0005 already records that authentication fails **closed**, opposite to
`BudgetStore`. Spelling out the cases:

| Situation | Answer |
|---|---|
| No credential presented | 401 |
| Credential presented, unknown | 401 |
| Credential presented, revoked | 401 |
| Snapshot refresh failing, snapshot still fresh | **serve** from last good snapshot |
| Snapshot older than `max_snapshot_age` | **401** — fail closed |

The last two are the honest middle and the only interesting decision here.
Hard-failing every request because a store blipped is an outage the store did
not have. Serving a week-old key set because refresh has been broken since
Tuesday is worse — a revoked key that still works is the failure this whole
increment exists to prevent. So: keep serving, but **bound it**, and make the
bound configurable and logged when exceeded.

## The store seam (persistent, shared across deployments)

The owner intends multiple proxy deployments sharing one store. That is
ADR-0005's shape, plus one consequence worth stating now:

```rust
trait CredentialStore: Send + Sync {
    /// Control-plane side. Async: a remote store can be slow or fail.
    async fn snapshot(&self) -> Result<KeySnapshot, StoreError>;
}
```

- **The hot path never calls this.** The control side polls or subscribes and
  publishes an immutable `KeySnapshot` through `ArcSwap`; workers do a
  lock-free load, exactly as `ClusterManager` does for host sets.
- **Revocation across instances is a staleness problem, and the bound is a
  product promise.** With one shared store and N proxies, a key revoked through
  the API keeps working on any instance that has not refreshed. State the
  window ("revocation takes effect within one refresh interval, default Ns"),
  make it configurable, and surface last-refresh age on the admin endpoint.
  With the in-memory store this window is zero, which is exactly why it must be
  designed now — it is invisible until it isn't.
- **Auth is the easy half to distribute; budgets are the hard half.** Keys are
  read-mostly and tolerate seconds of staleness. Spend counters are
  read-modify-write and do not. Do not let a working distributed
  `CredentialStore` imply the budget store is solved — different problem, and
  WP-34's fail-open policy is the opposite of this one's.

## Increments

- **2a — virtual keys, in-memory (buildable now).** `Authenticator` trait,
  `Principal`, HMAC-SHA-256 verification with constant-time compare, keys from
  config into an `ArcSwap` snapshot, fail closed, and **re-key the token
  limiter onto `Principal.tenant`**. No store, no admin CRUD. This alone makes
  the rate limit enforceable and closes the last v0.1.0 gate clause's
  precondition.
- **2b — `CredentialStore` trait + persistent embedded implementation**, with
  the refresh-interval and staleness bound above.
- **2c — OIDC/JWT as a second `Authenticator`.**
- **3 — tenants, account policies, budgets, admin CRUD** (WP-50 increment 3 as
  already planned).

## What this brief deliberately does not decide

Per-tenant model allow-lists reference WP-49's model catalogue, and budgets are
distinct from WP-34's rate limit (a spend ceiling is not a throttle — WP-42
draws that line). Both belong to increment 3 and are named here only so the
`TenantPolicy` shape does not have to change to accommodate them.
