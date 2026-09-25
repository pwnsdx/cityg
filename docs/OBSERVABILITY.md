# Observability

What the native delivery service (`cityg-api`) exposes to operators: logs,
Prometheus metrics and health endpoints. The Cloudflare Worker uses the
platform's logs and analytics instead
([`crates/cityg-worker/README.md`](../crates/cityg-worker/README.md)).

The delivery service sees no plaintext and no group secret, and its
telemetry is built to add as little metadata as possible: metrics are
aggregated by route, never by group, and logs name routes, not groups or
members.

## Logs

`cityg-api` logs through `tracing`:

* `RUST_LOG` sets the filter (default `info`; for example
  `RUST_LOG=cityg_api=debug,tower_http=info`);
* `LOG_FORMAT=json` switches from text to one JSON object per line.

Every request runs in a span `http_request` with `method`, `path` and
`request_id`, and logs `request started` and `request completed` (with
`status` and `latency_ms`). The request identifier comes from a valid UUID
in the `x-request-id` request header, or is generated, and is returned in
the `x-request-id` response header: quote it when reporting a problem.

Notable events:

| Event | Level | Meaning |
| --- | --- | --- |
| `rooms are journaled under <path>` | info | Startup with `state_path`. |
| `no state path configured: rooms live in memory only` | warn | Startup without `state_path`: a restart loses every room. |
| `metrics exporter disabled` | warn | The Prometheus recorder could not be installed; `/metrics` answers `metrics not available`. |
| `log-head subscription lagged by N notices` | warn | A WebSocket subscriber fell behind; it gets a `resync` notice. Raise `websocket_capacity` if frequent. |

## Metrics

`GET /metrics` serves the Prometheus text format.

| Metric | Type | Labels |
| --- | --- | --- |
| `http_requests_total` | counter | `method`, `path` |
| `http_responses_total` | counter | `method`, `path`, `status` |
| `http_request_duration_seconds` | histogram | `method`, `path`, `status` |

`path` is one of the API routes (`/v3/groups/commit`, ...), `/v3/ws`, a
health path, `/metrics`, or `unmatched` for anything else, so that arbitrary
request paths cannot grow the metric registry.

Useful queries:

```promql
# Throughput and server errors
sum(rate(http_requests_total[5m]))
sum(rate(http_responses_total{status=~"5.."}[5m]))

# Latency of commits (p95); commits of large groups carry large update paths
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{path="/v3/groups/commit"}[5m])) by (le))

# Commits that lost the race for their epoch (clients rebuild and retry)
sum(rate(http_responses_total{path="/v3/groups/commit",status="409"}[5m]))

# Protocol objects failing verification (buggy or malicious clients)
sum(rate(http_responses_total{status="422"}[5m])) by (path)

# Refused sessions and tokens (expired tokens, removed members)
sum(rate(http_responses_total{status=~"401|403"}[5m])) by (path)
```

How to read them:

* A steady share of `409` on `/v3/groups/commit` is normal when several
  members commit at once; a high share means members commit too often (the
  maintenance interval) or a client retries in a loop.
* `409` on `/v3/groups/send` means replayed or stale envelopes; `422` there
  means envelopes of an inactive epoch.
* `403` on `/v3/groups/log` follows removals and key rotations: removed
  members learn their removal that way, and a member that rotated its key
  opens a new session.
* `409` on `/v3/groups/join_request` means a device retried while its
  request was pending; many `/v3/groups/join_status` requests are joiners
  waiting for a commit (1 to 2 seconds each) before they commit their own
  entry.
* `/v3/groups/leaf_proofs` is the traffic of light members proving the
  senders of the messages they read.
* `413` means objects or groups over the configured limits
  (`max_group_size`, request size).

[`docs/examples/`](examples/) has a Prometheus configuration with example
alerts and a Grafana dashboard.

## Health

| Path | Use |
| --- | --- |
| `/health/live` | Liveness probe: the process serves requests. |
| `/health/ready` | Readiness probe. |
| `/health`, `/health/detailed` | JSON `{status, timestamp, version, uptime_seconds, checks}`; status `healthy`, `degraded` (HTTP 200) or `unhealthy` (HTTP 503). |

`scripts/healthcheck_api.sh <url> <timeout> <interval>` waits for a health
URL to answer, for start-up scripts and systemd units.

## Load and chaos testing

`cityg-stress` drives many simulated members against a managed or external
server and reads its metrics:

```bash
cargo run -p cityg-stress -- --workers 4 --rounds-per-worker 5 --require-metrics
```

It reports commit outcomes (accepted or lost epoch races), message delivery
and request latencies, and can restart the server or the clients during the
run (`--restart-every-secs`, `--client-restart-every-secs`). The nightly CI
job runs such a campaign; `scripts/run_restart_traffic_chaos.sh` and
`scripts/run_large_group_chaos.sh` wrap longer ones.
