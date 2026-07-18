//! Admin server (WP-25).
//!
//! Endpoints v1 (Envoy-compatible shapes; istioctl must parse `/config_dump`):
//! `/ready`, `/stats`, `/stats/prometheus`, `/clusters`, `/config_dump`,
//! `/listeners`, `/server_info`, `/drain_listeners?graceful`,
//! `/healthcheck/fail|ok`, `/logging`, `/quitquitquit`.
//!
//! Also hosts the per-request explain-mode endpoint (PLAN.md Part 7.1).
//! Runs on the control runtime with its own tiny HTTP server — never the data plane.
