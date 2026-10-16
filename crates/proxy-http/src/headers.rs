//! envoy-semantics.md S9 — header sanitization & standard mutations.
//!
//! Pure, synchronous header transforms only: every function here takes an
//! `&mut http::HeaderMap` (plus whatever small bits of context it needs) and
//! returns nothing async, does no I/O, and never reaches into
//! `proxy_config::ir`. The router is the caller that threads
//! config values (`use_remote_address`, `xff_num_trusted_hops`, ...) and the
//! live connection's remote address/transport into these functions.
//!
//! ⚠️ marks below correspond 1:1 to the `⚠️` marks in S9 of
//! `internal-docs/envoy-semantics.md`: the text itself says "verify against Envoy docs"
//! at these points. Where the semantics text does not resolve the ambiguity, the
//! choice made here is written down next to the `⚠️`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::{HeaderMap, HeaderName, HeaderValue};

/// Config knobs for [`apply_xff`] and [`resolve_trusted_address`], mirroring
/// Envoy's HCM-level `use_remote_address` / `xff_num_trusted_hops`.
pub struct XffOptions {
    /// `true`: append the downstream remote address to `x-forwarded-for`.
    /// `false` (Envoy's default): pass whatever XFF arrived untouched.
    pub use_remote_address: bool,
    /// Number of trusted proxy hops to skip, counting from the rightmost
    /// (most-recently-appended) entry of `x-forwarded-for`, when resolving
    /// "the" client address for a request that arrived through `N` trusted
    /// proxies ahead of us.
    pub xff_num_trusted_hops: u32,
}

const XFF: &str = "x-forwarded-for";

// Rust note: `HeaderName`/`HeaderValue` are separate types from `&str` because
// a header *name* is validated once (ASCII token, normalized) and a header
// *value* is validated separately (opaque bytes, no CR/LF/NUL) — see the
// non-UTF-8 handling below. `HeaderName::from_static` / a `const` name would
// panic on a bad literal at const-eval time, so it's safe to unwrap here: the
// string is a compile-time constant we control, not attacker input.
fn xff_name() -> HeaderName {
    HeaderName::from_static(XFF)
}

/// Split every `x-forwarded-for` header instance (there can be more than one
/// if a client or intermediate hop sent duplicates) into its comma-separated
/// tokens, trimmed, non-empty. Never panics on garbage input — a token that
/// isn't a valid IP address is still returned as a token (callers that need
/// an `IpAddr` parse it themselves and decide how to fail).
///
/// Rust note: `get_all` returns an iterator over *all* header instances with
/// this name (`HeaderMap` allows repeats), as opposed to `get`, which only
/// ever returns the first. XFF is logically a single comma-joined list, so we
/// flatten every instance's comma-split tokens into one `Vec`.
fn xff_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(XFF)
        .iter()
        .flat_map(|value| {
            // A non-UTF-8 header value can't be split into IP-address
            // tokens meaningfully; treat it as contributing zero tokens
            // rather than panicking or erroring.
            let s = value.to_str().unwrap_or("");
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn set_xff_tokens(headers: &mut HeaderMap, tokens: &[String]) {
    let joined = tokens.join(", ");
    // Rust note: `HeaderValue::from_str` fails on bytes that aren't legal in
    // a header value (e.g. an embedded CR/LF). Every token here came either
    // from a previous header value (already legal) or from `IpAddr::to_string`
    // (always legal), so the join is always legal too — but we still fall
    // back to leaving the header alone instead of unwrapping, since "never
    // panic on malformed input" is a hard rule.
    if let Ok(value) = HeaderValue::from_str(&joined) {
        headers.insert(xff_name(), value);
    }
}

/// S9 rule 1: `x-forwarded-for`.
///
/// `use_remote_address = true` appends the downstream remote address as a
/// new rightmost entry (collapsing any pre-existing multi-instance XFF into
/// one comma-joined header in the process — Envoy always emits XFF as a
/// single header). `use_remote_address = false` (Envoy's default) leaves
/// whatever XFF arrived completely untouched, including the case where it's
/// absent.
pub fn apply_xff(headers: &mut HeaderMap, remote: IpAddr, opts: &XffOptions) {
    if !opts.use_remote_address {
        return;
    }
    let mut tokens = xff_tokens(headers);
    tokens.push(remote.to_string());
    set_xff_tokens(headers, &tokens);
}

/// Resolve "the" client address per `xff_num_trusted_hops`, for the
/// `use_remote_address = false` case: with `N` trusted hops, skip the `N`
/// rightmost (most-recently-appended) XFF entries and take the next one.
/// `N = 0` means "trust the rightmost entry as-is"; `N` larger than the
/// number of entries falls back to the leftmost (original client-supplied)
/// entry, matching Envoy's saturating behavior rather than panicking or
/// returning nothing.
///
/// When `use_remote_address = true`, the resolved address is always the
/// downstream remote address itself — that's what [`apply_xff`] just
/// appended as the new rightmost entry.
///
/// Never panics on a garbage (non-IP) token: falls back to `remote`.
/// The client address limits attribute a request to (`StreamInfo::
/// client_address`). It is the TCP peer unless this is a non-edge HCM with
/// `xff_num_trusted_hops` set, where it is the `x-forwarded-for` entry those
/// trusted hops vouch for. With no trusted hops `x-forwarded-for` is never
/// read: the client can write it, and a limit keyed on it could be dodged by
/// sending a fresh value per request.
pub fn client_address(headers: &HeaderMap, remote: IpAddr, opts: &XffOptions) -> IpAddr {
    if opts.use_remote_address || opts.xff_num_trusted_hops == 0 {
        return remote;
    }
    resolve_trusted_address(headers, remote, opts)
}

pub fn resolve_trusted_address(headers: &HeaderMap, remote: IpAddr, opts: &XffOptions) -> IpAddr {
    if opts.use_remote_address {
        return remote;
    }
    let tokens = xff_tokens(headers);
    if tokens.is_empty() {
        return remote;
    }
    let hops = opts.xff_num_trusted_hops as usize;
    // Rust note: `saturating_sub` avoids an underflow panic when `hops >=
    // tokens.len()` — in that case we deliberately land on index 0 (the
    // leftmost/original entry) rather than wrapping around.
    let idx = (tokens.len() - 1).saturating_sub(hops);
    tokens
        .get(idx)
        .and_then(|t| t.parse::<IpAddr>().ok())
        .unwrap_or(remote)
}

/// RFC 1918 private ranges: `10/8`, `172.16/12`, `192.168/16`. Loopback
/// (`127/8`) is treated as private too, matching the "internal" intuition
/// for a directly-connected health check or local client (⚠️ S9: the plan
/// doesn't spell out whether loopback counts — this implementation includes
/// it).
fn is_private_v4(v4: Ipv4Addr) -> bool {
    if v4.is_loopback() {
        return true;
    }
    let o = v4.octets();
    match o[0] {
        10 => true,
        172 => (16..=31).contains(&o[1]),
        192 => o[1] == 168,
        _ => false,
    }
}

/// IPv6 unique-local (`fc00::/7`) plus loopback (`::1`). `fc00::/7` covers
/// the top 7 bits of the first byte being `1111110`, i.e. the first byte is
/// `0xfc` or `0xfd`.
fn is_private_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return true;
    }
    let first_byte = v6.octets()[0];
    (first_byte & 0xfe) == 0xfc
}

fn is_private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

/// S9 rule 2: is this an "internal" request?
///
/// ⚠️ S9's literal definition: "RFC1918 source address AND a single XFF
/// entry". This implementation reads "single" as "zero or one" — a request
/// with no XFF header at all (a direct connection, e.g. a health check hop)
/// is still internal if its source is private; a request with two or more
/// XFF entries is external even from a private source, since that shape
/// means at least one untrusted proxy already relayed it. This is the one
/// place S9 flags as needing verification against Envoy's docs at the pinned
/// version; if that verification turns up a stricter "must have exactly
/// one" reading, only the `tokens.len() <= 1` line below needs to change.
pub fn is_internal_request(headers: &HeaderMap, remote: IpAddr) -> bool {
    if !is_private_address(remote) {
        return false;
    }
    xff_tokens(headers).len() <= 1
}

/// S9 rule 3: `x-request-id`. Returns `true` if a fresh id was generated
/// (header was absent), `false` if an existing id was preserved untouched.
///
/// `gen` is a caller-supplied generator so tests can be deterministic and so
/// the real call site can plug in whatever randomness source `proxy-http`
/// ends up standardizing on — see [`generate_request_id`] for the seeded,
/// dependency-free default.
pub fn ensure_request_id(headers: &mut HeaderMap, gen: &mut dyn FnMut() -> String) -> bool {
    if headers.contains_key("x-request-id") {
        return false;
    }
    let id = gen();
    if let Ok(value) = HeaderValue::from_str(&id) {
        headers.insert(HeaderName::from_static("x-request-id"), value);
    }
    true
}

/// A small, seeded PRNG (splitmix64) used to expand a single `u64` seed into
/// request-id bytes without pulling in the `uuid` crate. It is not
/// cryptographically secure; request IDs are correlation tokens, not secrets,
/// matching Envoy's own use of UUIDs here.
///
/// **Seed this with [`seed_from_entropy`], never with a constant.** Under
/// ADR-0003 each worker thread owns its own state; if every worker started
/// from the same fixed seed they would all emit the *same* id sequence, and
/// `x-request-id` would collide across the fleet — silently destroying the
/// log correlation the header exists to provide.
///
/// Rust note: `&mut u64` as the "RNG state" is the whole seam — no trait
/// object, no struct, just a mutable integer the caller owns and threads
/// through calls. Each call mixes the state and returns a new pseudo-random
/// `u64`, so two calls from the same starting seed always produce the same
/// sequence (determinism for tests).
/// Draw a fresh, unpredictable seed for [`splitmix64`] — one per worker, at
/// worker startup. `rand` is already a workspace dependency (used by
/// `proxy-cluster`'s load balancers), so this costs nothing new.
///
/// Rust note: the point of separating "seed" from "generate" is that the
/// generator stays a pure function of its state (so tests can pin a seed and
/// get a reproducible sequence) while production still gets independent
/// streams per worker. Determinism is a *testing* affordance here, never the
/// runtime default.
pub fn seed_from_entropy() -> u64 {
    rand::random()
}

pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Generate a v4-shaped UUID string (`8-4-4-4-12` hex, version nibble `4`)
/// from a [`splitmix64`]-seeded RNG.
///
/// ⚠️ S9: Envoy encodes a tracing sample/force decision in the UUID's
/// variant nibble (the first hex digit of the third group, normally one of
/// `8`/`9`/`a`/`b` per RFC 4122). This function implements the *mechanism* —
/// `traced` selects `b` (Envoy's "traced" marker) vs. a plain RFC-4122
/// variant nibble drawn from the RNG (`8`/`9`/`a`) when untraced — but no
/// caller in this crate has a tracing decision to feed it yet (the router
/// has none to pass, and distributed tracing isn't wired up anywhere in the
/// data plane at this point). Every current caller should pass `false`,
/// which is a documented divergence from Envoy's parity behavior, not a
/// silent omission: once tracing lands, plumbing its sampling decision into
/// `traced` is the only change needed here.
pub fn generate_request_id(state: &mut u64, traced: bool) -> String {
    let hi = splitmix64(state).to_be_bytes();
    let lo = splitmix64(state).to_be_bytes();
    // Rust note: fixed-size arrays don't implement `Iterator` directly in a
    // way that concatenates nicely, so a plain 16-element array literal
    // (rather than `[hi, lo].concat()`, which would need a `Vec`) keeps this
    // allocation-free.
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&hi);
    bytes[8..].copy_from_slice(&lo);

    // RFC 4122 version nibble: top nibble of byte 6 forced to 4 ("version 4
    // / random"), low nibble stays random.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // RFC 4122 variant nibble: top nibble of byte 8 is normally one of
    // `8`/`9`/`a`/`b` (top 2 bits `10`). Envoy overloads this nibble to also
    // carry a trace sampling/force decision — see the doc comment above for
    // why `traced` only ever selects `b` vs. an RNG-drawn `8`/`9`/`a` here.
    let variant_high_nibble: u8 = if traced {
        0xb
    } else {
        match bytes[8] & 0b11 {
            0 => 0x8,
            1 => 0x9,
            _ => 0xa,
        }
    };
    bytes[8] = (bytes[8] & 0x0f) | (variant_high_nibble << 4);

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// S9 rule 4: strip `x-envoy-*` request headers from an external source —
/// they're trusted control headers an external client has no business
/// setting. (Internal sources keep them; call sites gate this on
/// [`is_internal_request`].) Also usable for the response direction: strip
/// internal `x-envoy-*` response headers before they reach an external
/// downstream client.
pub fn strip_envoy_headers_from_external(headers: &mut HeaderMap) {
    strip_prefix(headers, "x-envoy-");
}

/// Rust note: `HeaderMap` has no "remove while iterating" API — `remove`
/// takes `&mut self` and iteration borrows `&self`, so mutating mid-iteration
/// would be a double-borrow the compiler rejects. The fix is the standard
/// two-pass shape: collect the *names* to remove into an owned `Vec` first
/// (dropping the borrow), then remove them in a second pass.
fn strip_prefix(headers: &mut HeaderMap, prefix: &str) {
    let to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            name.as_str().len() >= prefix.len()
                && name.as_str()[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
        .cloned()
        .collect();
    for name in to_remove {
        // `HeaderMap::remove` removes *all* values for the name in one call
        // (unlike `HashMap::remove`, which would only make sense for a
        // single value) — exactly what we want for a multi-valued header.
        headers.remove(name);
    }
}

/// S9 rule 5: `x-forwarded-proto`, set from the downstream connection's
/// transport — `"https"` if TLS-terminated, `"http"` otherwise. Always
/// overwrites any pre-existing value: this header describes *our*
/// connection to the client, which an upstream client-supplied value can't
/// speak to truthfully.
pub fn set_forwarded_proto(headers: &mut HeaderMap, is_tls: bool) {
    let value = if is_tls { "https" } else { "http" };
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(value),
    );
}

/// S9 rule 6: hop-by-hop header sanitization. `connection`, `upgrade`,
/// `transfer-encoding`, `keep-alive`, and `proxy-connection` are always
/// stripped: they describe *this* hop's connection and framing, and
/// forwarding them lets one peer manage the other's connection (an upstream
/// `connection: close` would close the client's keep-alive connection).
/// Envoy strips the same set in both directions
/// (`ConnectionManagerUtility::mutateRequestHeaders` /
/// `mutateResponseHeaders`). `te` is stripped down to only `trailers` --
/// dropping every other `te` value (`gzip`, `deflate`, ...) but *keeping*
/// `trailers` if present, because gRPC-over-h2 depends on `te: trailers`
/// surviving the proxy hop to negotiate trailer support; dropping it
/// silently is a classic way to break gRPC.
///
/// Called by `codec::serve_one` on every request before the filter chain
/// and on every response after it. An upgrade uses
/// [`sanitize_upgrade_hop_by_hop`] instead.
pub fn sanitize_hop_by_hop(headers: &mut HeaderMap) {
    headers.remove(http::header::UPGRADE);
    sanitize_upgrade_hop_by_hop(headers);
}

/// [`sanitize_hop_by_hop`] for an upgrade (S10): everything except
/// `upgrade`, which names the protocol and is what the router's S10.1 gate
/// reads. `connection` is still stripped; each h1 codec re-synthesizes
/// `connection: upgrade` on the wire (`send_upstream_http1_upgrade` toward
/// the upstream, `serve_one` on a `101` toward the client), so a client's
/// extra tokens (`keep-alive, Upgrade`) never reach the upstream.
pub fn sanitize_upgrade_hop_by_hop(headers: &mut HeaderMap) {
    headers.remove(http::header::CONNECTION);
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(HeaderName::from_static("proxy-connection"));

    let trailers_present = headers.get_all(http::header::TE).iter().any(|v| {
        v.to_str()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .any(|t| t.eq_ignore_ascii_case("trailers"))
    });
    headers.remove(http::header::TE);
    if trailers_present {
        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
}

#[cfg(test)]
#[path = "headers/tests.rs"]
mod tests;
