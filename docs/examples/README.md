# City-G Deployment Examples

This directory contains runnable deployment examples for `cityg-api`, the
native delivery service of profile v0.2. A room has a single writer: run one
instance per state path, and shard by group identifier to scale out (see
[`docs/deployment.md`](../deployment.md)). The Cloudflare Worker deployment
is described in [`crates/cityg-worker/README.md`](../../crates/cityg-worker/README.md).

## Contents

- `docker-compose.yml`: API + Prometheus + Grafana stack.
- `cityg.env.example`: baseline environment variables for Compose/systemd.
- `cityg-api.service`: hardened systemd unit example.
- `kubernetes-deployment.yml`: reference Kubernetes manifest.
- `prometheus.yml`: Prometheus scrape + alerting baseline.
- `config-production.toml`: production-oriented config file sample.
- `grafana-datasources.yml`: Grafana datasource provisioning.
- `grafana-dashboards/`: Grafana dashboard provisioning files.

## Quick Start: Docker Compose

Run from this directory (`docs/examples`):

```bash
cp cityg.env.example cityg.env
docker compose up -d --build
```

Check service health:

```bash
curl -fsS http://127.0.0.1:8080/health/ready
curl -fsS http://127.0.0.1:8080/health/detailed
```

Rooms are journaled under `/var/lib/cityg/rooms` in the `cityg-data`
volume. The service needs no token or bootstrap key: members authenticate
with their device keys, and the creator of a room invites the others (see the
[GUI user guide](../gui-user-guide.md)).

Open dashboards:

- API: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (`admin` / `admin`)

Stop stack:

```bash
docker compose down
```

## Quick Start: systemd

1. Install binaries:

```bash
cargo build --release -p cityg-api
sudo install -m 0755 target/release/cityg-api /usr/local/bin/cityg-api
sudo install -m 0755 scripts/healthcheck_api.sh /usr/local/bin/healthcheck_api.sh
```

2. Install configuration:

```bash
sudo useradd --system --home /var/lib/cityg --shell /usr/sbin/nologin cityg || true
sudo mkdir -p /etc/cityg /var/lib/cityg
sudo cp docs/examples/cityg.env.example /etc/cityg/cityg.env
sudo chown -R cityg:cityg /var/lib/cityg
sudo chmod 0640 /etc/cityg/cityg.env
```

3. Install unit and start service:

```bash
sudo cp docs/examples/cityg-api.service /etc/systemd/system/cityg-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now cityg-api
```

4. Verify startup:

```bash
sudo systemctl status cityg-api --no-pager
./scripts/healthcheck_api.sh http://127.0.0.1:8080/health/ready 60 2
```

## Quick Start: Kubernetes

```bash
kubectl apply -f docs/examples/kubernetes-deployment.yml
kubectl get pods -n cityg
kubectl get svc -n cityg
```

The manifest runs one replica with the `Recreate` strategy on a
`ReadWriteOnce` volume, so that two pods never serve the same rooms.

## Runtime Verification Scripts

Use these scripts from the repository root:

```bash
# Security baseline (tests + server-blindness checks)
./scripts/security_review.sh

# Runtime smoke: members join, talk and leave through invite links, then
# the capacity check runs the full-group protocol test
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 1 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --jitter-max-secs 0 \
  --round-delay-secs 0 \
  --message-burst-count 1 \
  --message-burst-interval-ms 0 \
  --final-capacity-check
```

## Monitoring Queries

Use these Prometheus queries as a baseline:

```promql
sum(rate(http_requests_total[5m]))
sum(rate(http_responses_total{status=~"5.."}[5m]))
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))
```

## Security Checklist

Before production promotion:

- [ ] `./scripts/verify_no_secrets.sh` passes.
- [ ] `./scripts/security_review.sh` passes.
- [ ] Health probes wired to `/health/live` and `/health/ready`.
- [ ] Service runs as non-root user.
- [ ] `CITYG_SERVER_STATE_PATH` is on durable disk and backed up.
- [ ] TLS terminates in front of the service (session tokens are bearer secrets).
- [ ] Only one instance serves a given state path.

## Troubleshooting

```bash
# API logs (Compose)
docker compose logs -f cityg-api

# API logs (systemd)
sudo journalctl -u cityg-api -n 200 -f

# Stack status
docker compose ps

# Metrics endpoint
curl -fsS http://127.0.0.1:8080/metrics | head
```

For deeper guidance:

- [`docs/deployment.md`](../deployment.md)
- [`docs/OBSERVABILITY.md`](../OBSERVABILITY.md)
- [`docs/TROUBLESHOOTING.md`](../TROUBLESHOOTING.md)
