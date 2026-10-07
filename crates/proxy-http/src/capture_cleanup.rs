//! One bounded, worker-local cleanup owner; never one task per request.
use crate::stream_info::StreamInfo;
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
    time::Duration,
};
thread_local! {
    static STATES: RefCell<Vec<Weak<RefCell<StreamInfo>>>>=const{RefCell::new(Vec::new())};
    static STARTED: std::cell::Cell<bool>=const{std::cell::Cell::new(false)};
}
pub(crate) fn register(info: &Rc<RefCell<StreamInfo>>) {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        states.retain(|s| s.strong_count() > 0);
        states.push(Rc::downgrade(info));
    });
    if STARTED.with(|s| s.replace(true)) {
        return;
    }
    let mut changes = info.borrow().metadata_lease.as_ref().unwrap().changes();
    tokio::task::spawn_local(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! { _=tick.tick()=>{}, result=changes.changed()=>{if result.is_err(){break;}} }
            STATES.with(|states| {
                states.borrow_mut().retain(|weak| {
                    let Some(info) = weak.upgrade() else {
                        return false;
                    };
                    if let Ok(mut info) = info.try_borrow_mut() {
                        info.check_capture_gate();
                        return info.metadata_lease.is_some();
                    }
                    true
                })
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_observability::{
        capture::CaptureSupervisor,
        capture_policy::*,
        capture_transport::*,
        records::RequestRecordSink,
        stats::{MetadataDeliveryStats, StatsControl},
    };
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn disable_clears_idle_capture_state_and_never_resumes_it() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let id = proxy_observability::trace::TraceContext::new_root(false)
                    .trace_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let directory =
                    std::path::PathBuf::from(format!("/private/tmp/capture-cleanup-{id}"));
                std::fs::create_dir(&directory).unwrap();
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let uid = tokio::net::UnixStream::pair()
                    .unwrap()
                    .0
                    .peer_cred()
                    .unwrap()
                    .uid();
                let metadata = MetadataCapturePolicy::default();
                let config = EndUserCaptureConfig {
                    policy_version: metadata.effective_version("one"),
                    metadata,
                    endpoint: AgentTransportConfig {
                        socket_path: directory.join("agent.sock"),
                        expected_agent_uid: uid,
                        expected_node_id: "agent".into(),
                        producer_id: "proxy".into(),
                    },
                    budgets: CaptureBudgets::default(),
                    transport: CaptureTransportLimits::default(),
                    emergency_control: LocalCaptureControl {
                        unix_socket_path: directory.join("control.sock"),
                        operator_uid: uid,
                    },
                };
                let stats = StatsControl::new(1);
                let (supervisor, delivery) =
                    CaptureSupervisor::start(MetadataDeliveryStats::resolve(&stats)).unwrap();
                supervisor.configure(Some(config), 1).unwrap();
                let info = Rc::new(RefCell::new(StreamInfo::default()));
                {
                    let mut i = info.borrow_mut();
                    i.metadata_lease = supervisor.try_admit().unwrap();
                    i.metadata_enabled = true;
                    i.metadata_attempt_limit = 8;
                }
                let attempt = info
                    .borrow_mut()
                    .begin_attempt("provider", "host", Some("model".into()))
                    .unwrap();
                register(&info);
                {
                    let mut i = info.borrow_mut();
                    while i.begin_attempt("provider", "host", None).is_some() {}
                    assert!(i.attempts_truncated);
                    assert!(i.attempts.len() <= 8);
                }
                supervisor.set_disabled(true, 0).unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while supervisor.status().active_requests != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(info.borrow().attempts.is_empty());
                assert!(info.borrow().metadata_lease.is_none());
                assert_eq!(attempt.borrow().cluster.capacity(), 0);
                supervisor.set_disabled(false, 1).unwrap();
                assert!(info
                    .borrow_mut()
                    .begin_attempt("provider", "host", None)
                    .is_none());
                assert!(!delivery.shutdown(Duration::from_secs(1)).await);
                std::fs::remove_dir(directory).unwrap();
            })
            .await;
    }
}
