//! Integration tests for `proxy_core::tls` (WP-08 chunk B1): downstream and
//! upstream rustls factories built straight from the IR, handshaking over
//! `tokio::io::duplex` pipes (no real sockets needed since both factories'
//! `wrap` are generic over `AsyncRead + AsyncWrite`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{
    CaSource, DataSourceIR, DownstreamTlsSpec, SanMatcherIR, SanType, StringMatcherIR,
    TlsCertificateIR, TlsParametersIR, TlsVersion, UpstreamTlsSpec, ValidationContextIR,
};
use proxy_core::tls::{DownstreamTlsFactory, SdsSecretRegistry, UpstreamTlsFactory};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// A pre-generated (via `openssl genpkey`) 2048-bit RSA key, PKCS#8 PEM --
// rcgen/ring can *sign* with RSA but (without the `aws-lc-rs` backend, which
// needs a cmake toolchain we're deliberately avoiding -- see the WP-08 task
// notes) can't *generate* RSA keys, so the dual-cert test embeds one.
const RSA_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCTqRdE9Hfk0JVI
xm1L0/pCnijfoIVFq2Eab+f6alpA9yGbFAk6hI8v2lPmeH+77UuMVv+6PaL3tfQp
5HXc1g1eEg80aLbZ6w3aHDWfyowMWkOt3VfpSJq9Sjy5GvlQnmXHBmVsoSAjb3NT
vMhcoT4avTu3QpN08Zlz2qlHI7ck+1yW8KtusuOyIHIRCfukdRzMkWaPA5lZNARK
MYMXJ8MsKDMpFde4QqypJNTOEf8eURGdwmRv03lB3QToqhsVg8QXow1bNVkU5MnM
d1Go+6Z8Ol3EREpgtp1/iTr1lM1dtWztSYZtOugWc2Cp0WjvtFzVCT2dahs12heX
SN0idXIrAgMBAAECggEABq9WDVof/2zuBUBufEtZfiCY6x7iSbgrij3cu7qK4XwO
um2ayVps/RaeS8XSyphAnlbl9vGJajuDlU3xhBDww/x/UbkX5h+9Hc2/I7/QvVJs
0/c8XqRZ1Q4CV8L/3IV/SBZjCxr0UIZgKz9VttPZ8u30QSSzdkzlzJfup/jW9saU
2+2IDje7b20PrHj530waaEsk5f5L1MveMq3A2D8oyInKR8UfyUfu65EAqmJca7xX
b8rvdX2IRSahD9BgLLTW3m/NlMuwz+GSWCzkgGTv1+ZifQt5sdJdJ+ZL3jHjXcQt
+nXqFhcRIVL8ha9VDY24bY0yLT12Cf9nV3oARGxJiQKBgQDGTUWUNUP42XLB+ucv
fSwxvjktFbNecIvehxAG2tmqj8O0e95L8sQIO8P76a0hiSlSHYZb2RV1zf8ZYWRa
O6eyYbUCtdc8hFWXtGUaHQv5wLQsN+1dEN9cwA/myzk4ML2H/h2qfZOuLdCu+Jx6
jZoetGyHEVFSUYQ6NYakur/ZBQKBgQC+n76XjEhhCilogyQP3JD9UE2YX2lwkYma
oLVUByeckBdJpp/mVUPz78H7Mv65Ve5E4cmwBrzTgcRcsVcu8LkpVAcP24ePnbo7
LO5Z8tVWjOl4m51bH7CvxU1YQ77ugf7nufG+bVqAilGaFEWFIOR9hYI/cJqdn/Yl
9KsITyhFbwKBgGkWBetWluDHCyN0/RKTeNobfl1ABL/lUJnqZTncvEDA0utQQStq
SSw7z84ttUvyTe1wLAV8cvzs32Tp0a5nsqS7VptLFfbCAkHUnUdLYU9HKbPNJ4KM
MHIMbeDWjUoTujzZE4uH5L0HFnHC2dmwNJ5U6rZhHQFMpY/bUbD2LjipAoGAUa1+
686XAMVq4rY2UHmQwomTBfPz6ODjVhcAOyXpqiLvZ4Z2wynLuQ0FUA4UqPMR6f/Y
/IyWggX7TkBKe/l3TScM85V762SI9GwXIQF0ueYc76m17eKRQW9H6cb1W5rlzwKU
e6S9f5BE0MFY3GcwoDwBiA9GoL12qeLBGglY1w8CgYAkmoNroaLtlMc9yuotXvEW
ftXH1exAPxFtFRzfxD1V1Du8hrIwlGEtLOyOUgTUQoF2TW25ECtaFt2HRFYPnwkO
7TqEO0AxyAFJehappUq3Zcj35q/fkiPETxvE1nANFCRUHCBaW+l2EPR0DjrMNTa9
GdGIML90cFtpXr13uutgIg==
-----END PRIVATE KEY-----
";

// ------------------------------------------------------------ cert minting --

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn mint_ca(name: &str) -> Ca {
    let key = KeyPair::generate().expect("ecdsa keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key).expect("self-sign CA");
    Ca { cert, key }
}

/// Mint a leaf certificate signed by `ca`, with `sans` as DNS SANs, using
/// `key` (so callers can pass an ECDSA or RSA key).
fn mint_leaf(ca: &Ca, sans: &[&str], key: &KeyPair) -> rcgen::Certificate {
    let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(names).expect("leaf params");
    params.distinguished_name.push(DnType::CommonName, sans[0]);
    params.signed_by(key, &ca.cert, &ca.key).expect("sign leaf")
}

fn mint_self_signed(name: &str, key: &KeyPair) -> rcgen::Certificate {
    let mut params = CertificateParams::new(vec![name.to_string()]).expect("self-signed params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.self_signed(key).expect("self-sign")
}

fn tls_cert_ir(cert: &rcgen::Certificate, key: &KeyPair) -> TlsCertificateIR {
    TlsCertificateIR {
        cert_chain: DataSourceIR::Inline(cert.pem()),
        private_key: DataSourceIR::Inline(key.serialize_pem()),
    }
}

fn default_params() -> TlsParametersIR {
    TlsParametersIR {
        min_version: TlsVersion::V1_2,
        max_version: TlsVersion::V1_3,
        cipher_suites: vec![],
        ecdh_curves: vec![],
    }
}

fn trusted_ca_validation(ca: &Ca) -> ValidationContextIR {
    ValidationContextIR {
        ca: CaSource::TrustedCa(DataSourceIR::Inline(ca.cert.pem())),
        san_matchers: vec![],
        allow_expired_certificate: false,
    }
}

fn validation_with(
    ca: &Ca,
    san_matchers: Vec<SanMatcherIR>,
    allow_expired_certificate: bool,
) -> ValidationContextIR {
    ValidationContextIR {
        ca: CaSource::TrustedCa(DataSourceIR::Inline(ca.cert.pem())),
        san_matchers,
        allow_expired_certificate,
    }
}

/// Mint a leaf whose validity window is entirely in the past.
fn mint_expired_leaf(ca: &Ca, sans: &[&str], key: &KeyPair) -> rcgen::Certificate {
    let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(names).expect("leaf params");
    params.distinguished_name.push(DnType::CommonName, sans[0]);
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2000, 6, 1);
    params.signed_by(key, &ca.cert, &ca.key).expect("sign leaf")
}

// --------------------------------------------------------------- handshake --

/// Run a downstream/upstream handshake over an in-memory pipe and return the
/// connected (server, client) TLS streams.
async fn handshake(
    downstream: &DownstreamTlsFactory,
    upstream: &UpstreamTlsFactory,
    endpoint_host: &str,
) -> (
    tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
    tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
) {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_fut = downstream.wrap(server_io);
    let client_fut = upstream.wrap(client_io, endpoint_host);
    let (server, client) = tokio::try_join!(server_fut, client_fut).expect("handshake succeeds");
    (server, client)
}

// ----------------------------------------------------------------- tests ---

#[tokio::test]
async fn happy_path_round_trip_and_version() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (mut server, mut client) = handshake(&downstream, &upstream, "server.example.com").await;

    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 5];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    server.write_all(b"world").await.unwrap();
    server.flush().await.unwrap();
    let mut buf = [0u8; 5];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");
}

#[tokio::test]
async fn version_negotiation_falls_back_to_tls12() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(), // server: V1_2..=V1_3
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: TlsParametersIR {
            min_version: TlsVersion::V1_2,
            max_version: TlsVersion::V1_2, // client: capped at 1.2, the IR default
            cipher_suites: vec![],
            ecdh_curves: vec![],
        },
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

#[tokio::test]
async fn alpn_negotiates_h2() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(),
        alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec!["h2".to_string()],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
}

#[tokio::test]
async fn dual_cert_all_default_client_gets_ecdsa() {
    let ca = mint_ca("test CA");
    let ecdsa_key = KeyPair::generate().unwrap();
    let ecdsa_cert = mint_leaf(&ca, &["server.example.com"], &ecdsa_key);
    let rsa_key = KeyPair::from_pem(RSA_TEST_KEY_PEM).unwrap();
    let rsa_cert = mint_leaf(&ca, &["server.example.com"], &rsa_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![
            tls_cert_ir(&rsa_cert, &rsa_key),
            tls_cert_ir(&ecdsa_cert, &ecdsa_key),
        ],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer_certs = client
        .get_ref()
        .1
        .peer_certificates()
        .expect("peer certs present");
    assert_eq!(peer_certs[0].as_ref(), ecdsa_cert.der().as_ref());
}

#[tokio::test]
async fn no_validation_upstream_accepts_self_signed_server() {
    let key = KeyPair::generate().unwrap();
    let cert = mint_self_signed("self-signed.example.com", &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: None, // Envoy parity: no validation context = no verification.
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let _ = handshake(&downstream, &upstream, "self-signed.example.com").await;
}

#[tokio::test]
async fn trusted_ca_upstream_rejects_wrong_ca() {
    let real_ca = mint_ca("real CA");
    let other_ca = mint_ca("other CA");
    let key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&other_ca, &["server.example.com"], &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&real_ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_fut = downstream.wrap(server_io);
    let client_fut = upstream.wrap(client_io, "server.example.com");
    let result = tokio::try_join!(server_fut, client_fut);
    assert!(result.is_err(), "handshake against the wrong CA must fail");
}

#[tokio::test]
async fn trusted_ca_upstream_bypasses_hostname_mismatch() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    // Cert is only valid for "server.example.com"...
    let server_cert = mint_leaf(&ca, &["server.example.com"], &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    // ...but we connect with a totally different endpoint host/SNI. Envoy's
    // trusted_ca-only validation is chain-trust only, so this must succeed.
    let _ = handshake(&downstream, &upstream, "totally-different.example.org").await;
}

#[tokio::test]
async fn mtls_requires_client_cert_when_mandatory() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = mint_leaf(&ca, &["client.example.com"], &client_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: Some(trusted_ca_validation(&ca)),
        validation_sds_name: None,
        require_client_certificate: true,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    // No client cert presented -> handshake must fail.
    let upstream_no_cert = UpstreamTlsFactory::build(
        &UpstreamTlsSpec {
            sni: None,
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: None,
            validation: Some(trusted_ca_validation(&ca)),
        },
        "test",
    )
    .unwrap();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let result = tokio::try_join!(
        downstream.wrap(server_io),
        upstream_no_cert.wrap(client_io, "server.example.com")
    );
    assert!(
        result.is_err(),
        "mTLS handshake without a client cert must fail"
    );

    // CA-signed client cert presented -> handshake succeeds.
    let upstream_with_cert = UpstreamTlsFactory::build(
        &UpstreamTlsSpec {
            sni: None,
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: Some(tls_cert_ir(&client_cert, &client_key)),
            validation: Some(trusted_ca_validation(&ca)),
        },
        "test",
    )
    .unwrap();
    let _ = handshake(&downstream, &upstream_with_cert, "server.example.com").await;
}

#[tokio::test]
async fn hot_reload_serves_new_certificate() {
    let ca = mint_ca("test CA");
    let key_a = KeyPair::generate().unwrap();
    let cert_a = mint_leaf(&ca, &["server.example.com"], &key_a);
    let key_b = KeyPair::generate().unwrap();
    let cert_b = mint_leaf(&ca, &["server.example.com"], &key_b);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&cert_a, &key_a)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream = UpstreamTlsFactory::build(
        &UpstreamTlsSpec {
            sni: None,
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: None,
            validation: Some(trusted_ca_validation(&ca)),
        },
        "test",
    )
    .unwrap();

    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer = client.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(peer, cert_a.der().as_ref());
    drop(client);

    downstream
        .update_certificates(&[tls_cert_ir(&cert_b, &key_b)], "test reload")
        .unwrap();

    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer = client.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(peer, cert_b.der().as_ref());
}

// --------------------------------------------------- SAN matchers (chunk B2) --

/// Build a downstream (mTLS) + upstream pair whose *upstream* validation
/// context carries `san_matchers`, and run one handshake -- the shared
/// scaffolding every SAN-matcher test below needs on the server-cert-check
/// side (upstream verifying the downstream's served cert).
async fn handshake_with_upstream_san_matchers(
    ca: &Ca,
    server_cert: &rcgen::Certificate,
    server_key: &KeyPair,
    san_matchers: Vec<SanMatcherIR>,
) -> Result<
    (
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
        tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    ),
    std::io::Error,
> {
    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(server_cert, server_key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(validation_with(ca, san_matchers, false)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_fut = downstream.wrap(server_io);
    let client_fut = upstream.wrap(client_io, "server.example.com");
    tokio::try_join!(server_fut, client_fut)
}

fn exact_dns_matcher(value: &str) -> SanMatcherIR {
    SanMatcherIR {
        san_type: SanType::Dns,
        matcher: StringMatcherIR::Exact {
            value: value.to_string(),
            ignore_case: false,
        },
    }
}

#[tokio::test]
async fn san_matcher_dns_exact_match_succeeds() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let result = handshake_with_upstream_san_matchers(
        &ca,
        &cert,
        &key,
        vec![exact_dns_matcher("server.example.com")],
    )
    .await;
    assert!(result.is_ok(), "matching SAN must succeed");
}

#[tokio::test]
async fn san_matcher_dns_no_match_fails() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let result = handshake_with_upstream_san_matchers(
        &ca,
        &cert,
        &key,
        vec![exact_dns_matcher("totally-different.example.org")],
    )
    .await;
    assert!(result.is_err(), "non-matching SAN must fail");
}

#[tokio::test]
async fn san_matcher_ignore_case_matches_different_casing() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let matcher = SanMatcherIR {
        san_type: SanType::Dns,
        matcher: StringMatcherIR::Exact {
            value: "SERVER.EXAMPLE.COM".to_string(),
            ignore_case: true,
        },
    };
    let result = handshake_with_upstream_san_matchers(&ca, &cert, &key, vec![matcher]).await;
    assert!(result.is_ok(), "ignore_case exact match must succeed");
}

#[tokio::test]
async fn san_matcher_safe_regex_matches() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let matcher = SanMatcherIR {
        san_type: SanType::Dns,
        matcher: StringMatcherIR::SafeRegex(regex::Regex::new(r"^server\.[a-z]+\.com$").unwrap()),
    };
    let result = handshake_with_upstream_san_matchers(&ca, &cert, &key, vec![matcher]).await;
    assert!(result.is_ok(), "safe_regex match must succeed");
}

#[tokio::test]
async fn san_matcher_multiple_matches_only_second_still_succeeds() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let result = handshake_with_upstream_san_matchers(
        &ca,
        &cert,
        &key,
        vec![
            exact_dns_matcher("does-not-match.example.org"),
            exact_dns_matcher("server.example.com"),
        ],
    )
    .await;
    assert!(
        result.is_ok(),
        "OR semantics: a match on any matcher must succeed"
    );
}

#[tokio::test]
async fn san_matcher_downstream_client_cert_dns_match_succeeds() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = mint_leaf(&ca, &["client.example.com"], &client_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: Some(validation_with(
            &ca,
            vec![exact_dns_matcher("client.example.com")],
            false,
        )),
        validation_sds_name: None,
        require_client_certificate: true,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: Some(tls_cert_ir(&client_cert, &client_key)),
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let _ = handshake(&downstream, &upstream, "server.example.com").await;
}

#[tokio::test]
async fn san_matcher_downstream_client_cert_dns_mismatch_fails() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = mint_leaf(&ca, &["client.example.com"], &client_key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&server_cert, &server_key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: Some(validation_with(
            &ca,
            vec![exact_dns_matcher("nobody.example.com")],
            false,
        )),
        validation_sds_name: None,
        require_client_certificate: true,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: Some(tls_cert_ir(&client_cert, &client_key)),
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let result = tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    );
    assert!(
        result.is_err(),
        "client cert SAN mismatch must fail the mTLS handshake"
    );
}

// ---------------------------------------------- allow_expired_certificate --

#[tokio::test]
async fn expired_certificate_rejected_by_default() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let expired_cert = mint_expired_leaf(&ca, &["server.example.com"], &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&expired_cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(validation_with(&ca, vec![], false)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let result = tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    );
    assert!(result.is_err(), "expired cert must be rejected by default");
}

#[tokio::test]
async fn allow_expired_certificate_accepts_expired_cert_with_right_ca() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let expired_cert = mint_expired_leaf(&ca, &["server.example.com"], &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&expired_cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(validation_with(&ca, vec![], true)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let _ = handshake(&downstream, &upstream, "server.example.com").await;
}

#[tokio::test]
async fn allow_expired_certificate_still_rejects_wrong_ca() {
    let real_ca = mint_ca("real CA");
    let other_ca = mint_ca("other CA");
    let key = KeyPair::generate().unwrap();
    let expired_cert = mint_expired_leaf(&other_ca, &["server.example.com"], &key);

    let downstream_spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(&expired_cert, &key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream = DownstreamTlsFactory::build(&downstream_spec, "test").unwrap();

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        // allow_expired_certificate = true, but signed by the wrong CA.
        validation: Some(validation_with(&real_ca, vec![], true)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let result = tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    );
    assert!(
        result.is_err(),
        "allow_expired_certificate must not bypass chain-trust failures"
    );
}

// Rust note: a compile-time assertion, not a runtime test -- if either
// factory stops being `Send + Sync` this function simply fails to compile.
// Both types cross control/worker-thread boundaries (ADR-0003), so this is a
// load-bearing property, not a nice-to-have.
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn factories_are_send_sync() {
    assert_send_sync::<DownstreamTlsFactory>();
    assert_send_sync::<UpstreamTlsFactory>();
}

// ---------------------------------------------------------------------------
// WP-22 increment 2a: an SDS-named chain binds with an empty cert set.

/// The whole point of the empty build: the listener comes up, accepts the TCP
/// connection, and fails the handshake -- it never serves in the clear, and it
/// never refuses to start. `update_certificates` (the SDS delivery path, wired
/// in increment 2b) then makes the same factory serve without a rebuild.
#[tokio::test]
async fn an_sds_named_chain_builds_empty_then_serves_after_delivery() {
    let ca = mint_ca("test CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);

    let downstream_spec = DownstreamTlsSpec {
        certificates: vec![],
        certificate_sds_names: vec!["server-cert".to_string()],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    let downstream =
        DownstreamTlsFactory::build(&downstream_spec, "test").expect("an SDS chain must build");

    let upstream_spec = UpstreamTlsSpec {
        sni: None,
        params: default_params(),
        alpn_protocols: vec![],
        client_certificate: None,
        validation: Some(trusted_ca_validation(&ca)),
    };
    let upstream = UpstreamTlsFactory::build(&upstream_spec, "test").unwrap();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let err = tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    )
    .expect_err("a chain with no certificates yet must fail the handshake");
    assert!(
        !format!("{err}").is_empty(),
        "the handshake must fail with a reason"
    );

    // Delivery: the same factory, no rebuild.
    downstream
        .update_certificates(&[tls_cert_ir(&server_cert, &server_key)], "test")
        .expect("SDS delivery must load");
    let (mut server, mut client) = handshake(&downstream, &upstream, "server.example.com").await;
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

/// The invariant `DownstreamTlsSpec::certificates` documents -- exactly one of
/// the two is set -- is enforced by lowering. A hand-built spec that breaks it
/// must still be refused here rather than yielding a listener that binds and
/// can never serve.
#[test]
fn a_spec_with_neither_certificates_nor_sds_names_is_refused() {
    let spec = DownstreamTlsSpec {
        certificates: vec![],
        certificate_sds_names: vec![],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    // Rust note: `DownstreamTlsFactory` is not `Debug`, so `expect_err` (which
    // needs to format the Ok side) does not apply -- match the error out.
    let Err(err) = DownstreamTlsFactory::build(&spec, "test") else {
        panic!("neither inline certificates nor SDS names must not build");
    };
    assert!(
        format!("{err}").contains("at least one certificate is required"),
        "got: {err}"
    );
}

// ---------------------------------------------------------------------------
// WP-22 increment 2b: `SdsSecretRegistry` -- the seam that maps a published
// SDS secret NAME back to the `DownstreamTlsFactory` instances that named it.
// See `crates/proxy-core/src/tls/secret_registry.rs`'s module doc for the two
// orderings these tests pin independently.

/// A `DownstreamTlsSpec` naming exactly one SDS secret and no inline
/// certificates -- the shape `build_listener_tls` hands to
/// `SdsSecretRegistry::register` for a chain like this.
fn sds_only_spec(name: &str) -> DownstreamTlsSpec {
    DownstreamTlsSpec {
        certificates: vec![],
        certificate_sds_names: vec![name.to_string()],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    }
}

fn upstream_for(ca: &Ca) -> UpstreamTlsFactory {
    UpstreamTlsFactory::build(
        &UpstreamTlsSpec {
            sni: None,
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: None,
            validation: Some(trusted_ca_validation(ca)),
        },
        "test",
    )
    .unwrap()
}

/// "Factory first, secret later" (the ordinary case, per the module doc): a
/// factory registers with an empty cert set, so its first handshake fails --
/// then `SdsSecretRegistry::publish` hot-swaps in the delivered cert on the
/// SAME factory, with no rebuild, and the next handshake serves it.
#[tokio::test]
async fn publish_then_serve() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let downstream = Arc::new(
        DownstreamTlsFactory::build(&sds_only_spec("cert-1"), "test")
            .expect("an SDS-only chain must build with an empty cert set"),
    );
    let upstream = upstream_for(&ca);

    let registry = SdsSecretRegistry::new();
    registry
        .register(&["cert-1".to_string()], &downstream, "test")
        .expect("registering with nothing published yet must succeed");

    // Empty cert set: the handshake fails.
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    )
    .expect_err("an SDS-named chain with nothing published yet must fail the handshake");

    // Publish: the same factory now serves it, no rebuild.
    registry
        .publish("cert-1", vec![tls_cert_ir(&cert, &key)])
        .expect("publish must reach the registered factory");

    let (mut server, mut client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer = client.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(peer, cert.der().as_ref());
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

/// WP-22 acceptance: rotating an SDS certificate while new TLS connections
/// are continuously handshaking must not expose an empty or partially-built
/// resolver. Every connection sees either the complete old certificate or the
/// complete new certificate, and the new certificate becomes observable
/// without rebuilding the serving factory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_rotation_under_tls_load_has_no_handshake_failures() {
    const WORKERS: usize = 16;
    const HANDSHAKES_PER_WORKER: usize = 32;
    const ROTATE_AFTER: usize = 64;

    let ca = mint_ca("test CA");
    let key_a = KeyPair::generate().unwrap();
    let cert_a = mint_leaf(&ca, &["server.example.com"], &key_a);
    let key_b = KeyPair::generate().unwrap();
    let cert_b = mint_leaf(&ca, &["server.example.com"], &key_b);
    let cert_a_der = cert_a.der().as_ref().to_vec();
    let cert_b_der = cert_b.der().as_ref().to_vec();

    let downstream = Arc::new(
        DownstreamTlsFactory::build(&sds_only_spec("rotating-cert"), "test")
            .expect("an SDS-only chain must build with an empty cert set"),
    );
    let upstream = Arc::new(upstream_for(&ca));
    let registry = SdsSecretRegistry::new();
    registry
        .register(&["rotating-cert".to_string()], &downstream, "test")
        .unwrap();
    registry
        .publish("rotating-cert", vec![tls_cert_ir(&cert_a, &key_a)])
        .unwrap();

    let completed = Arc::new(AtomicUsize::new(0));
    let saw_old = Arc::new(AtomicUsize::new(0));
    let saw_new = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(tokio::sync::Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let downstream = Arc::clone(&downstream);
        let upstream = Arc::clone(&upstream);
        let completed = Arc::clone(&completed);
        let saw_old = Arc::clone(&saw_old);
        let saw_new = Arc::clone(&saw_new);
        let start = Arc::clone(&start);
        let cert_a_der = cert_a_der.clone();
        let cert_b_der = cert_b_der.clone();
        workers.push(tokio::spawn(async move {
            start.wait().await;
            for _ in 0..HANDSHAKES_PER_WORKER {
                let (_server, client) =
                    handshake(&downstream, &upstream, "server.example.com").await;
                let peer = client.get_ref().1.peer_certificates().unwrap()[0]
                    .as_ref()
                    .to_vec();
                if peer == cert_a_der {
                    saw_old.fetch_add(1, Ordering::Relaxed);
                } else if peer == cert_b_der {
                    saw_new.fetch_add(1, Ordering::Relaxed);
                } else {
                    panic!("handshake observed neither complete SDS certificate");
                }
                completed.fetch_add(1, Ordering::Release);
                tokio::task::yield_now().await;
            }
        }));
    }

    start.wait().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while completed.load(Ordering::Acquire) < ROTATE_AFTER {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TLS load did not begin before the rotation deadline");

    registry
        .publish("rotating-cert", vec![tls_cert_ir(&cert_b, &key_b)])
        .expect("rotation must update the live serving factory");

    for worker in workers {
        worker.await.expect("TLS load worker must not fail");
    }

    assert_eq!(
        completed.load(Ordering::Acquire),
        WORKERS * HANDSHAKES_PER_WORKER
    );
    assert!(
        saw_old.load(Ordering::Relaxed) > 0,
        "load must observe the initially published certificate"
    );
    assert!(
        saw_new.load(Ordering::Relaxed) > 0,
        "load must observe the rotated certificate"
    );
}

/// "Secret first, factory later" (the normal case, per the module doc): the
/// control plane's delivery already arrived by the time a rebuilt factory
/// registers -- `register` must replay the cached cert immediately, with no
/// second `publish` call, rather than leaving the factory unserved until a
/// resend that may never come.
#[tokio::test]
async fn late_registration_serves_immediately_without_a_second_publish() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let registry = SdsSecretRegistry::new();
    // Published before any factory has registered for this name.
    registry
        .publish("cert-2", vec![tls_cert_ir(&cert, &key)])
        .expect("publishing to a name with no factory yet must still be Ok");

    let downstream = Arc::new(
        DownstreamTlsFactory::build(&sds_only_spec("cert-2"), "test")
            .expect("an SDS-only chain must build with an empty cert set"),
    );
    // Registering must replay the cached cert -- no further `publish` call
    // below, on purpose.
    registry
        .register(&["cert-2".to_string()], &downstream, "test")
        .expect("register must hot-swap in the already-delivered cert");

    let upstream = upstream_for(&ca);
    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer = client.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(peer, cert.der().as_ref());
}

/// A dropped factory must not keep the registry's bookkeeping growing (or
/// keep a stale `Weak` around forever): once the only `Arc` referencing a
/// registered factory is dropped, a later `publish` for its name must still
/// be `Ok`, must not panic, and `registered_factory_count` must read the
/// dead entry as pruned.
#[tokio::test]
async fn pruning_drops_dead_factories_without_error() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let registry = SdsSecretRegistry::new();
    let downstream = Arc::new(
        DownstreamTlsFactory::build(&sds_only_spec("cert-3"), "test")
            .expect("an SDS-only chain must build with an empty cert set"),
    );
    registry
        .register(&["cert-3".to_string()], &downstream, "test")
        .unwrap();
    assert_eq!(registry.registered_factory_count("cert-3"), 1);

    drop(downstream);

    let result = registry.publish("cert-3", vec![tls_cert_ir(&cert, &key)]);
    assert!(
        result.is_ok(),
        "publishing to a name whose only factory has been dropped must not error: {result:?}"
    );
    assert_eq!(
        registry.registered_factory_count("cert-3"),
        0,
        "the dead factory must be pruned, not counted as still live"
    );
}

/// A name nobody has ever registered a factory for is not an error --
/// `publish` caches it, and a factory that registers for that name later
/// still gets caught up, exactly as in the "secret first, factory later"
/// test above, but exercised from the angle of `publish`'s own return value
/// on an orphaned name.
#[tokio::test]
async fn publish_to_an_unregistered_name_is_ok_and_delivered_on_a_later_register() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);

    let registry = SdsSecretRegistry::new();
    let result = registry.publish("cert-4", vec![tls_cert_ir(&cert, &key)]);
    assert!(
        result.is_ok(),
        "publishing to a name with no registered factory must be Ok: {result:?}"
    );
    assert_eq!(registry.registered_factory_count("cert-4"), 0);

    let downstream = Arc::new(
        DownstreamTlsFactory::build(&sds_only_spec("cert-4"), "test")
            .expect("an SDS-only chain must build with an empty cert set"),
    );
    registry
        .register(&["cert-4".to_string()], &downstream, "test")
        .unwrap();
    assert_eq!(registry.registered_factory_count("cert-4"), 1);

    let upstream = upstream_for(&ca);
    let (_server, client) = handshake(&downstream, &upstream, "server.example.com").await;
    let peer = client.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(peer, cert.der().as_ref());
}

/// Explicit removal clears every live certificate resolver and the replay
/// cache. Existing factories fail closed again, and a later registration
/// cannot resurrect the removed certificate without a new delivery.
#[tokio::test]
async fn removal_fails_closed_all_certificate_consumers_and_clears_replay() {
    let ca = mint_ca("test CA");
    let key = KeyPair::generate().unwrap();
    let cert = mint_leaf(&ca, &["server.example.com"], &key);
    let upstream = upstream_for(&ca);
    let registry = SdsSecretRegistry::new();

    let first = Arc::new(DownstreamTlsFactory::build(&sds_only_spec("shared"), "test").unwrap());
    let second = Arc::new(DownstreamTlsFactory::build(&sds_only_spec("shared"), "test").unwrap());
    registry
        .register(&["shared".to_string()], &first, "test")
        .unwrap();
    registry
        .register(&["shared".to_string()], &second, "test")
        .unwrap();
    registry
        .publish("shared", vec![tls_cert_ir(&cert, &key)])
        .unwrap();
    let _ = handshake(&first, &upstream, "server.example.com").await;
    let _ = handshake(&second, &upstream, "server.example.com").await;

    registry.remove("shared").unwrap();
    for downstream in [&first, &second] {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        tokio::try_join!(
            downstream.wrap(server_io),
            upstream.wrap(client_io, "server.example.com")
        )
        .expect_err("every registered certificate consumer must fail after removal");
    }

    let late = Arc::new(DownstreamTlsFactory::build(&sds_only_spec("shared"), "test").unwrap());
    registry
        .register(&["shared".to_string()], &late, "test")
        .unwrap();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(
        late.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    )
    .expect_err("removed certificate must not replay to a later registration");

    registry
        .remove("unknown")
        .expect("removing an unknown, unregistered secret must succeed");
}

/// A dynamic validation context is fail-closed before SDS delivers the CA,
/// then updates the same serving factory without rebuilding its certificates.
/// This pins the distinct trust-anchor seam (an atomic ServerConfig swap), not
/// the certificate resolver seam exercised by the tests above.
#[tokio::test]
async fn validation_context_sds_delivery_unblocks_mtls_on_the_same_factory() {
    let ca = mint_ca("client CA");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = mint_leaf(&ca, &["server.example.com"], &server_key);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = mint_leaf(&ca, &["client.example.com"], &client_key);

    let downstream = Arc::new(
        DownstreamTlsFactory::build(
            &DownstreamTlsSpec {
                certificates: vec![tls_cert_ir(&server_cert, &server_key)],
                certificate_sds_names: vec![],
                params: default_params(),
                alpn_protocols: vec![],
                validation: None,
                validation_sds_name: Some("client-ca".to_string()),
                require_client_certificate: true,
                disable_stateless_session_resumption: false,
            },
            "test",
        )
        .unwrap(),
    );
    let upstream = UpstreamTlsFactory::build(
        &UpstreamTlsSpec {
            sni: None,
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: Some(tls_cert_ir(&client_cert, &client_key)),
            validation: Some(trusted_ca_validation(&ca)),
        },
        "test",
    )
    .unwrap();

    let registry = SdsSecretRegistry::new();
    registry
        .register_validation_context("client-ca", &downstream, "test")
        .unwrap();
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    )
    .expect_err("a validation context not yet delivered over SDS must fail closed");

    registry
        .publish_validation_context("client-ca", trusted_ca_validation(&ca))
        .expect("a usable dynamic trust anchor must update the registered factory");
    let _ = handshake(&downstream, &upstream, "server.example.com").await;

    registry
        .remove("client-ca")
        .expect("removing a validation context must restore pending verification");
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::try_join!(
        downstream.wrap(server_io),
        upstream.wrap(client_io, "server.example.com")
    )
    .expect_err("removed validation context must fail closed again");

    registry
        .publish_validation_context("client-ca", trusted_ca_validation(&ca))
        .expect("a later delivery must unblock verification again");
    let _ = handshake(&downstream, &upstream, "server.example.com").await;

    let bad_update = registry.publish_validation_context(
        "client-ca",
        ValidationContextIR {
            ca: CaSource::TrustedCa(DataSourceIR::Inline("not a PEM bundle".to_string())),
            san_matchers: vec![],
            allow_expired_certificate: false,
        },
    );
    assert!(bad_update.is_err(), "invalid trust anchors must NACK");
    let _ = handshake(&downstream, &upstream, "server.example.com").await;
}
