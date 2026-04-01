use reqwest::{Client, StatusCode, Url};
use serde_json::Value;

use super::*;

const WORKER_POLICY_PATH: &str = "/__cloudflare/policy";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum EndpointMode {
    #[default]
    Unknown,
    DirectApi,
    WorkerEdge,
}

impl EndpointMode {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unclassified endpoint",
            Self::DirectApi => "Direct API endpoint",
            Self::WorkerEdge => "Worker edge",
        }
    }
}

fn hinted_endpoint_mode(server_url: &str) -> EndpointMode {
    let host = Url::parse(server_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));

    match host.as_deref() {
        Some(host) if host.ends_with(".workers.dev") || host.ends_with(".pages.dev") => {
            EndpointMode::WorkerEdge
        }
        _ => EndpointMode::Unknown,
    }
}

fn worker_policy_looks_valid(payload: &Value) -> bool {
    payload
        .get("room_durable_object_routes")
        .is_some_and(Value::is_array)
        && payload
            .get("unsupported_native_routes")
            .is_some_and(Value::is_array)
}

async fn probe_endpoint_mode(server_url: &str) -> EndpointMode {
    let hinted = hinted_endpoint_mode(server_url);
    let url = format!("{}{}", server_url.trim_end_matches('/'), WORKER_POLICY_PATH);
    let response = match Client::new().get(url).send().await {
        Ok(response) => response,
        Err(_) => return hinted,
    };

    if response.status().is_success() {
        return match response.json::<Value>().await {
            Ok(payload) if worker_policy_looks_valid(&payload) => EndpointMode::WorkerEdge,
            _ => hinted,
        };
    }

    if response.status() == StatusCode::NOT_FOUND {
        return EndpointMode::DirectApi;
    }

    hinted
}

impl AppModel {
    pub(super) fn ensure_endpoint_mode_probe(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session) = &self.session else {
            self.endpoint_mode = EndpointMode::Unknown;
            self.endpoint_mode_server_url = None;
            self.endpoint_mode_task = None;
            return;
        };

        let server_url = session.server_url.clone();
        if self.endpoint_mode_task.is_some() {
            return;
        }
        if self.endpoint_mode_server_url.as_deref() == Some(server_url.as_str())
            && self.endpoint_mode != EndpointMode::Unknown
        {
            return;
        }

        self.endpoint_mode_server_url = Some(server_url.clone());

        let this = cx.weak_entity();
        let task = cx.spawn(async move |_, cx| {
            let probe_server_url = server_url.clone();
            let probe = match Tokio::spawn_result(cx, async move {
                Ok::<_, anyhow::Error>(probe_endpoint_mode(&probe_server_url).await)
            }) {
                Ok(task) => task,
                Err(err) => {
                    warn!("failed to schedule endpoint-mode probe: {err}");
                    let _ = this.update(cx, |model, _| {
                        model.endpoint_mode_task = None;
                    });
                    return;
                }
            };

            let mode = match probe.await {
                Ok(mode) => mode,
                Err(err) => {
                    warn!("endpoint-mode probe task failed: {err}");
                    EndpointMode::Unknown
                }
            };

            let _ = this.update(cx, |model, cx| {
                model.endpoint_mode_task = None;
                if model
                    .session
                    .as_ref()
                    .is_none_or(|session| session.server_url != server_url)
                {
                    return;
                }

                let changed = model.endpoint_mode != mode;
                model.endpoint_mode = mode;
                model.endpoint_mode_server_url = Some(server_url.clone());

                if changed {
                    match mode {
                        EndpointMode::WorkerEdge => {
                            model.record_activity(
                                ActivityKind::Connection,
                                "Detected Worker edge routing",
                            );
                        }
                        EndpointMode::DirectApi => {
                            model.record_activity(
                                ActivityKind::Connection,
                                "Detected direct API routing",
                            );
                        }
                        EndpointMode::Unknown => {}
                    }
                    cx.notify();
                }
            });
        });

        self.endpoint_mode_task = Some(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_dev_host_hints_worker_edge() {
        assert_eq!(
            hinted_endpoint_mode("https://cityg.example.workers.dev"),
            EndpointMode::WorkerEdge
        );
        assert_eq!(
            hinted_endpoint_mode("https://cityg.example.pages.dev"),
            EndpointMode::WorkerEdge
        );
        assert_eq!(
            hinted_endpoint_mode("https://cityg.example.com"),
            EndpointMode::Unknown
        );
    }

    #[test]
    fn worker_policy_payload_requires_route_arrays() {
        let payload = serde_json::json!({
            "room_durable_object_routes": [],
            "unsupported_native_routes": [],
        });
        assert!(worker_policy_looks_valid(&payload));

        let invalid = serde_json::json!({
            "room_durable_object_routes": "nope",
        });
        assert!(!worker_policy_looks_valid(&invalid));
    }
}
