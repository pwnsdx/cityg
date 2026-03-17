use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub updated_at: Option<Instant>,
    pub accept_epoch_ok: u64,
    pub refresh_conflicts: u64,
    pub pivot_refresh_409: u64,
    pub accept_p50_ms: Option<f64>,
    pub accept_p95_ms: Option<f64>,
    pub accept_p99_ms: Option<f64>,
}

fn parse_metric_value(text: &str, name: &str, label_fragments: &[&str]) -> Option<f64> {
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(name) || line.starts_with('#') {
            continue;
        }
        if !label_fragments.iter().all(|fragment| line.contains(fragment)) {
            continue;
        }
        let value = line.split_whitespace().last()?;
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

pub fn parse_metrics_snapshot(text: &str, now: Instant) -> MetricsSnapshot {
    MetricsSnapshot {
        updated_at: Some(now),
        accept_epoch_ok: parse_metric_value(text, "cityg_accept_epoch_total", &["result=\"ok\""])
            .unwrap_or(0.0) as u64,
        refresh_conflicts: parse_metric_value(
            text,
            "cityg_refresh_pivot_conflict_total",
            &["reason=\"payload_diverges\""],
        )
        .unwrap_or(0.0) as u64,
        pivot_refresh_409: parse_metric_value(
            text,
            "http_responses_total",
            &[
                "method=\"POST\"",
                "path=\"/v1/pivot/refresh\"",
                "status=\"409\"",
            ],
        )
        .unwrap_or(0.0) as u64,
        accept_p50_ms: parse_metric_value(
            text,
            "http_request_duration_seconds",
            &[
                "method=\"POST\"",
                "path=\"/v1/accept_epoch\"",
                "status=\"200\"",
                "quantile=\"0.5\"",
            ],
        )
        .map(|seconds| seconds * 1000.0),
        accept_p95_ms: parse_metric_value(
            text,
            "http_request_duration_seconds",
            &[
                "method=\"POST\"",
                "path=\"/v1/accept_epoch\"",
                "status=\"200\"",
                "quantile=\"0.95\"",
            ],
        )
        .map(|seconds| seconds * 1000.0),
        accept_p99_ms: parse_metric_value(
            text,
            "http_request_duration_seconds",
            &[
                "method=\"POST\"",
                "path=\"/v1/accept_epoch\"",
                "status=\"200\"",
                "quantile=\"0.99\"",
            ],
        )
        .map(|seconds| seconds * 1000.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metrics_extracts_counts_and_quantiles() {
        let text = r#"
cityg_accept_epoch_total{result="ok"} 123
cityg_refresh_pivot_conflict_total{reason="payload_diverges"} 7
http_responses_total{method="POST",path="/v1/pivot/refresh",status="409"} 7
http_request_duration_seconds{method="POST",path="/v1/accept_epoch",status="200",quantile="0.5"} 0.041
http_request_duration_seconds{method="POST",path="/v1/accept_epoch",status="200",quantile="0.95"} 0.067
http_request_duration_seconds{method="POST",path="/v1/accept_epoch",status="200",quantile="0.99"} 0.089
"#;
        let snapshot = parse_metrics_snapshot(text, Instant::now());
        assert_eq!(snapshot.accept_epoch_ok, 123);
        assert_eq!(snapshot.refresh_conflicts, 7);
        assert_eq!(snapshot.pivot_refresh_409, 7);
        assert_eq!(snapshot.accept_p50_ms, Some(41.0));
        assert_eq!(snapshot.accept_p95_ms, Some(67.0));
        assert_eq!(snapshot.accept_p99_ms, Some(89.0));
    }
}
