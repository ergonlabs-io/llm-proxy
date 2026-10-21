//! Chargeback tags through the real auth filter factory: config parsing,
//! resolution onto `StreamInfo`, header handling and the drop counter.

use super::*;
use prost_reflect::{MapKey, Value};

const SECRET: &str = "operator-hmac-secret";

fn message(name: &str) -> DynamicMessage {
    DynamicMessage::new(
        proxy_api::descriptor_pool()
            .get_message_by_name(name)
            .expect("compiled into proxy-api"),
    )
}

/// `ChargebackTags { allowed, from_header, max_tags, max_value_bytes }`.
fn policy(
    allowed: &[(&str, &[&str])],
    from_header: bool,
    max_tags: u32,
    max_value_bytes: u32,
) -> DynamicMessage {
    let mut msg = message("llmproxy.filters.v0.ChargebackTags");
    let allowed = allowed
        .iter()
        .map(|(key, values)| {
            let mut entry = message("llmproxy.filters.v0.AllowedTag");
            entry.set_field_by_name("key", Value::String(key.to_string()));
            entry.set_field_by_name(
                "values",
                Value::List(
                    values
                        .iter()
                        .map(|v| Value::String(v.to_string()))
                        .collect(),
                ),
            );
            Value::Message(entry)
        })
        .collect();
    msg.set_field_by_name("allowed", Value::List(allowed));
    msg.set_field_by_name("from_header", Value::Bool(from_header));
    msg.set_field_by_name("max_tags", Value::U32(max_tags));
    msg.set_field_by_name("max_value_bytes", Value::U32(max_value_bytes));
    msg
}

fn tagged_key(
    key_id: &str,
    tenant: &str,
    plaintext: &str,
    tags: &[(&str, &str)],
) -> DynamicMessage {
    let mut vk = virtual_key(
        key_id,
        tenant,
        &digest_hex(SECRET.as_bytes(), plaintext),
        false,
    );
    vk.set_field_by_name(
        "tags",
        Value::Map(
            tags.iter()
                .map(|(k, v)| (MapKey::String(k.to_string()), Value::String(v.to_string())))
                .collect(),
        ),
    );
    vk
}

fn config_with(keys: Vec<DynamicMessage>, tags: Option<DynamicMessage>) -> DynamicMessage {
    let mut config = authentication(inline_secret(SECRET), keys);
    if let Some(tags) = tags {
        config.set_field_by_name("chargeback_tags", Value::Message(tags));
    }
    config
}

/// A factory context carrying a stats registry, as production builds have.
fn ctx_with_registry() -> (FactoryContext, Arc<proxy_observability::stats::Registry>) {
    let ctx = FactoryContext::default();
    let registry = proxy_observability::stats::StatsControl::new(1).registry();
    ctx.shared
        .get_or_try_init("", "", crate::usage_filter::STATS_REGISTRY_KEY, || {
            Ok(Arc::clone(&registry) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .unwrap();
    (ctx, registry)
}

/// Runs one request through a fresh filter; returns its tags and whether
/// the tag header was still on the request afterwards.
fn send(
    factory: &dyn FilterInstanceFactory,
    bearer: &str,
    header: &[&str],
) -> (proxy_observability::chargeback::ChargebackTags, bool) {
    let mut filter = factory.create_filter();
    let mut cb = TestCallbacks::new(Some(route_named("r1")));
    let mut head = request_headers(Some(bearer));
    for value in header {
        head.headers
            .append("x-cost-tags", HeaderValue::from_str(value).unwrap());
    }
    filter.decode_headers(&mut cb, &mut head, true);
    assert!(cb.local_reply.is_none(), "request must be admitted");
    let tags = cb.stream_info.borrow().auth.tags.clone();
    (tags, head.headers.contains_key("x-cost-tags"))
}

fn tags(pairs: &[(&str, &str)]) -> proxy_observability::chargeback::ChargebackTags {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn dropped(registry: &proxy_observability::stats::Registry) -> Vec<String> {
    proxy_observability::stats::prometheus_render::render(registry)
        .lines()
        .filter(|line| line.starts_with("envoy_llmproxy_chargeback_tags_dropped_total{"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn without_a_policy_no_tags_are_attributed_and_the_header_is_not_read() {
    let config = config_with(
        vec![tagged_key(
            "key-1",
            "tenant-a",
            "llmp_k1",
            &[("team", "infra")],
        )],
        None,
    );
    let factory = AuthFilterFactory
        .create(&config, &FactoryContext::default())
        .unwrap();
    let (got, header_kept) = send(factory.as_ref(), "Bearer llmp_k1", &["project=search"]);
    assert!(got.is_empty(), "{got:?}");
    assert!(header_kept, "an unread header is forwarded unchanged");
}

#[test]
fn a_disabled_header_is_neither_read_nor_removed() {
    let config = config_with(
        vec![tagged_key(
            "key-1",
            "tenant-a",
            "llmp_k1",
            &[("team", "infra")],
        )],
        Some(policy(&[("team", &[]), ("project", &[])], false, 0, 0)),
    );
    let factory = AuthFilterFactory
        .create(&config, &FactoryContext::default())
        .unwrap();
    let (got, header_kept) = send(factory.as_ref(), "Bearer llmp_k1", &["project=search"]);
    assert_eq!(got, tags(&[("team", "infra")]));
    assert!(header_kept);
}

/// The acceptance case: a header tag cannot override the key's metadata,
/// and every other drop reason is counted under its own finite label.
#[test]
fn key_metadata_wins_over_the_header_and_drops_are_counted() {
    let (ctx, registry) = ctx_with_registry();
    let config = config_with(
        vec![tagged_key(
            "key-1",
            "tenant-a",
            "llmp_k1",
            &[("team", "infra")],
        )],
        Some(policy(
            &[
                ("team", &["infra", "search"]),
                ("project", &[]),
                ("env", &[]),
            ],
            true,
            2,
            8,
        )),
    );
    let factory = AuthFilterFactory.create(&config, &ctx).unwrap();
    let (got, header_kept) = send(
        factory.as_ref(),
        "Bearer llmp_k1",
        &["team=search, project=p, owner=x"],
    );
    assert_eq!(got, tags(&[("project", "p"), ("team", "infra")]));
    assert!(!header_kept, "a read header never reaches the provider");

    // Over-long, then over the count (key tag plus two header tags, cap 2).
    send(factory.as_ref(), "Bearer llmp_k1", &["project=123456789"]);
    send(factory.as_ref(), "Bearer llmp_k1", &["project=p,env=prod"]);
    // Malformed: dropped whole, and the request still goes through.
    let (got, _) = send(factory.as_ref(), "Bearer llmp_k1", &["project"]);
    assert_eq!(got, tags(&[("team", "infra")]));

    let lines = dropped(&registry);
    for (reason, count) in [
        ("malformed", 1),
        ("not_allowed", 1),
        ("over_count", 1),
        ("overridden", 1),
        ("too_long", 1),
    ] {
        let want = format!("reason=\"{reason}\"");
        let line = lines
            .iter()
            .find(|l| l.contains(&want))
            .unwrap_or_else(|| panic!("no {reason} series in {lines:?}"));
        assert!(line.ends_with(&format!(" {count}")), "{line}");
    }
}

/// No Prometheus series gains a tag label: many distinct accepted and
/// refused tag values leave the series count where one request put it, and
/// no rendered line names a tag value.
#[test]
fn many_distinct_tag_values_add_no_metric_series() {
    let (ctx, registry) = ctx_with_registry();
    let config = config_with(
        vec![tagged_key("key-1", "tenant-a", "llmp_k1", &[])],
        Some(policy(&[("project", &[])], true, 0, 16)),
    );
    let factory = AuthFilterFactory.create(&config, &ctx).unwrap();
    let series = || {
        proxy_observability::stats::prometheus_render::render(&registry)
            .lines()
            .filter(|line| !line.starts_with('#'))
            .count()
    };
    // Exercise every drop reason once so each series exists.
    send(factory.as_ref(), "Bearer llmp_k1", &["project=warm,team=x"]);
    send(
        factory.as_ref(),
        "Bearer llmp_k1",
        &["project=xxxxxxxxxxxxxxxxx"],
    );
    send(factory.as_ref(), "Bearer llmp_k1", &["bad"]);
    let before = series();
    for i in 0..500 {
        let (got, _) = send(
            factory.as_ref(),
            "Bearer llmp_k1",
            &[&format!("project=p{i},team{i}=v{i}")],
        );
        assert_eq!(got, tags(&[("project", &format!("p{i}"))]));
        send(
            factory.as_ref(),
            "Bearer llmp_k1",
            &[&format!("project=long{i:0>16}")],
        );
    }
    assert_eq!(series(), before, "tag values must never become series");
    let rendered = proxy_observability::stats::prometheus_render::render(&registry);
    assert!(!rendered.contains("p499"), "{rendered}");
}

/// A JWT principal carries no key metadata, so its tags come from the
/// header alone.
#[test]
fn a_jwt_principal_gets_header_tags_only() {
    let key = jwt_test_key();
    let mut config = authentication_with_jwt(
        inline_secret(SECRET),
        vec![jwt_provider(
            "tenant",
            Some("https://issuer.example"),
            Some("llm-proxy"),
            vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
        )],
    );
    config.set_field_by_name(
        "chargeback_tags",
        Value::Message(policy(&[("project", &[])], true, 0, 0)),
    );
    let factory = AuthFilterFactory
        .create(&config, &FactoryContext::default())
        .unwrap();
    let token = sign_test_jwt(
        key,
        "key-1",
        &jwt_claims(
            "tenant-j",
            r#","iss":"https://issuer.example","aud":"llm-proxy""#,
        ),
    );
    let (got, header_kept) = send(factory.as_ref(), &jwt_bearer(&token), &["project=search"]);
    assert_eq!(got, tags(&[("project", "search")]));
    assert!(!header_kept);
}

/// Tags are resolved from the authenticated key's own metadata: two
/// tenants' keys on one chain never see each other's tags, and a header
/// cannot name a tenant.
#[test]
fn a_request_carries_only_its_own_keys_tags() {
    let config = config_with(
        vec![
            tagged_key("key-a", "tenant-a", "llmp_ka", &[("team", "alpha")]),
            tagged_key("key-b", "tenant-b", "llmp_kb", &[("team", "beta")]),
        ],
        Some(policy(&[("team", &[]), ("project", &[])], true, 0, 0)),
    );
    let factory = AuthFilterFactory
        .create(&config, &FactoryContext::default())
        .unwrap();
    let (a, _) = send(
        factory.as_ref(),
        "Bearer llmp_ka",
        &["team=beta,tenant=tenant-b"],
    );
    assert_eq!(a, tags(&[("team", "alpha")]));
    let (b, _) = send(factory.as_ref(), "Bearer llmp_kb", &[]);
    assert_eq!(b, tags(&[("team", "beta")]));
}

#[test]
fn malformed_tag_config_is_rejected_with_its_field_path() {
    let cases: Vec<(DynamicMessage, &str)> = vec![
        (
            config_with(vec![], Some(policy(&[], true, 0, 0))),
            "typed_config.chargeback_tags.allowed",
        ),
        (
            config_with(vec![], Some(policy(&[("Team", &[])], true, 0, 0))),
            "typed_config.chargeback_tags.allowed[0].key",
        ),
        (
            config_with(vec![], Some(policy(&[("team", &["a b"])], true, 0, 0))),
            "typed_config.chargeback_tags.allowed[0].values[0]",
        ),
        (
            config_with(vec![], Some(policy(&[("team", &[])], true, 33, 0))),
            "typed_config.chargeback_tags.max_tags",
        ),
        (
            config_with(vec![], Some(policy(&[("team", &[])], true, 0, 257))),
            "typed_config.chargeback_tags.max_value_bytes",
        ),
        (
            config_with(
                vec![tagged_key(
                    "key-1",
                    "tenant-a",
                    "llmp_k1",
                    &[("team", "a,b")],
                )],
                None,
            ),
            "typed_config.virtual_keys[0].tags",
        ),
    ];
    for (config, want) in cases {
        match parse_config(&config) {
            Err(ConfigError::InvalidValue { field_path, .. }) => assert_eq!(field_path, want),
            other => panic!("{want}: expected InvalidValue, got {other:?}"),
        }
    }
}

/// Static key tags live in the per-serve control plane, which a reload
/// reuses, so a reload that changes them is refused like any key change.
/// The tag policy is not a boot input: a reload may change it.
#[test]
fn static_key_tags_are_a_boot_input_and_the_policy_is_not() {
    let boot = |key_tags: &[(&str, &str)], policy_msg: Option<DynamicMessage>| {
        parse_config(&config_with(
            vec![tagged_key("key-1", "tenant-a", "llmp_k1", key_tags)],
            policy_msg,
        ))
        .unwrap()
        .boot_inputs
    };
    let running = boot(&[("team", "infra")], None);
    assert!(boot(&[("team", "infra")], None).refusal(&running).is_none());
    assert!(boot(&[("team", "search")], None)
        .refusal(&running)
        .is_some());
    assert!(boot(&[], None).refusal(&running).is_some());
    assert!(boot(
        &[("team", "infra")],
        Some(policy(&[("team", &[])], true, 0, 0))
    )
    .refusal(&running)
    .is_none());
}

/// A JWT provider at `https://issuer.example` mapping `(claim, tag)` pairs.
fn claim_tag_provider(claim_tags: &[(&str, &str)]) -> DynamicMessage {
    let key = jwt_test_key();
    let mut provider = jwt_provider(
        "tenant",
        Some("https://issuer.example"),
        Some("llm-proxy"),
        vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
    );
    let entries = claim_tags
        .iter()
        .map(|(claim, tag)| {
            let mut entry = message("llmproxy.filters.v0.ClaimTag");
            entry.set_field_by_name("claim", Value::String(claim.to_string()));
            entry.set_field_by_name("tag", Value::String(tag.to_string()));
            Value::Message(entry)
        })
        .collect();
    provider.set_field_by_name("claim_tags", Value::List(entries));
    provider
}

fn claim_tag_config(claim_tags: &[(&str, &str)], tags: Option<DynamicMessage>) -> DynamicMessage {
    let mut config =
        authentication_with_jwt(inline_secret(SECRET), vec![claim_tag_provider(claim_tags)]);
    if let Some(tags) = tags {
        config.set_field_by_name("chargeback_tags", Value::Message(tags));
    }
    config
}

/// A signed token for `tenant-j` with `extra` claims (`,"k":v` JSON text).
fn claim_token(extra: &str) -> String {
    jwt_bearer(&sign_test_jwt(
        jwt_test_key(),
        "key-1",
        &jwt_claims(
            "tenant-j",
            &format!(r#","iss":"https://issuer.example","aud":"llm-proxy"{extra}"#),
        ),
    ))
}

/// Mapped claims set tags the header cannot override. A value outside the
/// allow-list, a missing claim and a non-string claim are each dropped and
/// counted, the header still cannot fill those keys, and the request is
/// served.
#[test]
fn jwt_claims_set_tags_the_header_cannot_override() {
    let (ctx, registry) = ctx_with_registry();
    let config = claim_tag_config(
        &[("department", "team"), ("cost_center", "project")],
        Some(policy(
            &[
                ("team", &["infra", "search"]),
                ("project", &[]),
                ("env", &[]),
            ],
            true,
            0,
            0,
        )),
    );
    let factory = AuthFilterFactory.create(&config, &ctx).unwrap();

    let (got, header_kept) = send(
        factory.as_ref(),
        &claim_token(r#","department":"infra","cost_center":"ads""#),
        &["team=search,project=x,env=prod"],
    );
    assert_eq!(
        got,
        tags(&[("team", "infra"), ("project", "ads"), ("env", "prod")])
    );
    assert!(!header_kept);

    // Not allowed, and missing: the header fills neither.
    let (got, _) = send(
        factory.as_ref(),
        &claim_token(r#","department":"marketing""#),
        &["team=search,project=y"],
    );
    assert_eq!(got, tags(&[]));
    // Not a string, and outside the value alphabet.
    let (got, _) = send(
        factory.as_ref(),
        &claim_token(r#","department":7,"cost_center":"a b""#),
        &[],
    );
    assert_eq!(got, tags(&[]));

    let lines = dropped(&registry);
    for (reason, count) in [
        ("claim_missing", 1),
        ("malformed", 2),
        ("not_allowed", 1),
        ("overridden", 4),
    ] {
        let want = format!("reason=\"{reason}\"");
        let line = lines
            .iter()
            .find(|l| l.contains(&want))
            .unwrap_or_else(|| panic!("no {reason} series in {lines:?}"));
        assert!(line.ends_with(&format!(" {count}")), "{line}");
    }
    let rendered = proxy_observability::stats::prometheus_render::render(&registry);
    assert!(!rendered.contains("marketing"), "{rendered}");
}

/// A claim value over `max_value_bytes` is dropped by the policy's own cap.
#[test]
fn an_over_long_claim_value_is_dropped_as_too_long() {
    let (ctx, registry) = ctx_with_registry();
    let config = claim_tag_config(
        &[("cost_center", "project")],
        Some(policy(&[("project", &[])], false, 0, 4)),
    );
    let factory = AuthFilterFactory.create(&config, &ctx).unwrap();
    let (got, _) = send(
        factory.as_ref(),
        &claim_token(r#","cost_center":"abcde""#),
        &[],
    );
    assert_eq!(got, tags(&[]));
    assert!(dropped(&registry)
        .iter()
        .any(|l| l.contains("reason=\"too_long\"") && l.ends_with(" 1")));
}

#[test]
fn malformed_claim_tags_are_rejected_with_their_field_path() {
    let allowed = || Some(policy(&[("team", &[])], false, 0, 0));
    let cases: Vec<(DynamicMessage, &str)> = vec![
        (
            claim_tag_config(&[("department", "team")], None),
            "typed_config.jwt_providers[0].claim_tags",
        ),
        (
            claim_tag_config(&[("department", "owner")], allowed()),
            "typed_config.jwt_providers[0].claim_tags[0].tag",
        ),
        (
            claim_tag_config(&[("department", "Team")], allowed()),
            "typed_config.jwt_providers[0].claim_tags[0].tag",
        ),
        (
            claim_tag_config(&[("", "team")], allowed()),
            "typed_config.jwt_providers[0].claim_tags[0].claim",
        ),
        (
            claim_tag_config(&[("department", "team"), ("group", "team")], allowed()),
            "typed_config.jwt_providers[0].claim_tags[1].tag",
        ),
    ];
    for (config, want) in cases {
        match parse_config(&config) {
            Err(ConfigError::InvalidValue { field_path, .. }) => assert_eq!(field_path, want),
            other => panic!("{want}: expected InvalidValue, got {other:?}"),
        }
    }
}
