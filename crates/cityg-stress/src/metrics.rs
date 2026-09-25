//! Delivery-service metrics scraped from the native server's `/metrics`.

use std::time::Instant;

const COMMIT_PATH: &str = "path=\"/v3/groups/commit\"";
const SEND_PATH: &str = "path=\"/v3/groups/send\"";

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub updated_at: Option<Instant>,
    /// Commits the service accepted.
    pub commits_ok: u64,
    /// Commits refused as stale (409): another commit won the epoch.
    pub commit_conflicts: u64,
    /// Messages the service accepted.
    pub messages_ok: u64,
    pub commit_p50_ms: Option<f64>,
    pub commit_p95_ms: Option<f64>,
    pub commit_p99_ms: Option<f64>,
}

fn parse_metric_value(text: &str, name: &str, label_fragments: &[&str]) -> Option<f64> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with(name) {
            continue;
        }
        if !label_fragments
            .iter()
            .all(|fragment| line.contains(fragment))
        {
            continue;
        }
        if let Some(Ok(parsed)) = line.split_whitespace().last().map(str::parse::<f64>) {
            return Some(parsed);
        }
    }
    None
}

fn count(text: &str, path: &str, status: &str) -> u64 {
    let status = format!("status=\"{status}\"");
    parse_metric_value(
        text,
        "http_responses_total",
        &["method=\"POST\"", path, status.as_str()],
    )
    .unwrap_or(0.0) as u64
}

fn commit_latency_ms(text: &str, quantile: &str) -> Option<f64> {
    let quantile = format!("quantile=\"{quantile}\"");
    parse_metric_value(
        text,
        "http_request_duration_seconds",
        &[
            "method=\"POST\"",
            COMMIT_PATH,
            "status=\"200\"",
            quantile.as_str(),
        ],
    )
    .map(|seconds| seconds * 1000.0)
}

pub fn parse_metrics_snapshot(text: &str, now: Instant) -> MetricsSnapshot {
    MetricsSnapshot {
        updated_at: Some(now),
        commits_ok: count(text, COMMIT_PATH, "200"),
        commit_conflicts: count(text, COMMIT_PATH, "409"),
        messages_ok: count(text, SEND_PATH, "200"),
        commit_p50_ms: commit_latency_ms(text, "0.5"),
        commit_p95_ms: commit_latency_ms(text, "0.95"),
        commit_p99_ms: commit_latency_ms(text, "0.99"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metrics_extracts_counts_and_quantiles() {
        let text = r#"
# TYPE http_responses_total counter
http_responses_total{method="POST",path="/v3/groups/commit",status="200"} 123
http_responses_total{method="POST",path="/v3/groups/commit",status="409"} 7
http_responses_total{method="POST",path="/v3/groups/send",status="200"} 40
http_request_duration_seconds{method="POST",path="/v3/groups/commit",status="200",quantile="0.5"} 0.041
http_request_duration_seconds{method="POST",path="/v3/groups/commit",status="200",quantile="0.95"} 0.067
http_request_duration_seconds{method="POST",path="/v3/groups/commit",status="200",quantile="0.99"} 0.089
http_request_duration_seconds{method="POST",path="/v3/groups/commit",status="200",quantile="0.999"} not-a-number
"#;
        let snapshot = parse_metrics_snapshot(text, Instant::now());
        assert_eq!(snapshot.commits_ok, 123);
        assert_eq!(snapshot.commit_conflicts, 7);
        assert_eq!(snapshot.messages_ok, 40);
        assert_eq!(snapshot.commit_p50_ms, Some(41.0));
        assert_eq!(snapshot.commit_p95_ms, Some(67.0));
        assert_eq!(snapshot.commit_p99_ms, Some(89.0));
        assert_eq!(commit_latency_ms(text, "0.999"), None);

        let empty = parse_metrics_snapshot("", Instant::now());
        assert_eq!(empty.commits_ok, 0);
        assert_eq!(empty.commit_p95_ms, None);
    }
}
