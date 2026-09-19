use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_xds::{FileSource, FileSourceError};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn temp_path(extension: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("llm-proxy-xds-{nonce}.{extension}"))
}

#[test]
fn yaml_source_loads_and_watcher_detects_one_replacement() {
    let path = temp_path("yaml");
    std::fs::write(
        &path,
        format!("type_url: {CDS}\nversion_info: v1\nnonce: n1\nresources: []\n"),
    )
    .expect("write source");
    let source = FileSource::new(&path, CDS);
    let mut watcher = source.watcher();
    assert!(watcher.changed().expect("initial stamp"));
    assert!(!watcher.changed().expect("unchanged stamp"));
    let response = source.load().expect("load response");
    assert_eq!(response.version_info, "v1");
    std::fs::write(
        &path,
        format!("type_url: {CDS}\nversion_info: v2\nnonce: n2\nresources: []\n"),
    )
    .expect("replace source");
    assert!(watcher.changed().expect("replacement stamp"));
    std::fs::remove_file(path).expect("cleanup");
}

#[test]
fn protobuf_source_loads_and_wrong_type_is_rejected() {
    let path = temp_path("pb");
    let bytes = DiscoveryResponse {
        type_url: CDS.to_string(),
        version_info: "v1".to_string(),
        ..Default::default()
    }
    .encode_to_vec();
    std::fs::write(&path, bytes).expect("write source");
    let source = FileSource::new(
        &path,
        "type.googleapis.com/envoy.config.listener.v3.Listener",
    );
    let error = source.load().expect_err("type mismatch must reject");
    assert!(matches!(error, FileSourceError::TypeMismatch { .. }));
    std::fs::remove_file(path).expect("cleanup");
}

#[test]
fn malformed_source_reports_path_and_does_not_update_watcher() {
    let path = temp_path("json");
    std::fs::write(&path, "{\"type_url\":").expect("write source");
    let source = FileSource::new(&path, CDS);
    let error = source.load().expect_err("malformed source must reject");
    assert!(format!("{error}").contains(&path.display().to_string()));
    std::fs::remove_file(path).expect("cleanup");
}
