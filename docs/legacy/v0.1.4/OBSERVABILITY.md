# CityG API Observability Guide

This guide covers the observability features implemented in the CityG API, including logging, metrics, tracing, and health checks.

## Table of Contents

- [Overview](#overview)
- [Structured Logging](#structured-logging)
- [Request Tracing & Correlation IDs](#request-tracing--correlation-ids)
- [Performance Metrics](#performance-metrics)
- [Health Checks](#health-checks)
- [Resilience Features](#resilience-features)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Overview

The CityG API includes comprehensive observability features designed to make debugging and monitoring in production environments straightforward and effective.

### Key Features

- **Structured Logging**: JSON-formatted logs for easy parsing and analysis
- **Request Tracing**: Correlation IDs for tracking requests across services
- **Performance Metrics**: Prometheus-compatible metrics for latency, throughput, and errors
- **Health Checks**: Multiple endpoints for liveness, readiness, and detailed health status
- **Circuit Breaker**: Automatic failure detection and recovery
- **Retry Logic**: Exponential backoff for transient failures
- **Offline Queue**: Message queuing when network is unavailable

## Structured Logging

### Configuration

The API supports two logging formats:

1. **Human-readable** (default): For development and debugging
2. **JSON structured**: For production environments

#### Setting Log Format

```bash
# Development (human-readable)
export LOG_FORMAT=text
cargo run --bin cityg-api

# Production (JSON structured)
export LOG_FORMAT=json
cargo run --bin cityg-api
```

#### Setting Log Level

```bash
# Set global log level
export RUST_LOG=info

# Set per-module log levels
export RUST_LOG=cityg_api=debug,tower_http=info

# Enable all traces
export RUST_LOG=trace
```

### Log Levels

- `ERROR`: Critical errors that need immediate attention
- `WARN`: Warning conditions that should be investigated
- `INFO`: Important informational messages (default)
- `DEBUG`: Detailed debugging information
- `TRACE`: Very detailed tracing information

### JSON Log Structure

When `LOG_FORMAT=json`, logs are emitted in the following structure:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "target": "cityg_api",
  "fields": {
    "message": "request started",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "method": "POST",
    "path": "/v1/send_message",
    "status": 200,
    "latency_ms": 45
  },
  "span": {
    "name": "http_request",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

## Request Tracing & Correlation IDs

### Overview

Every request is assigned a unique correlation ID (UUID v4) that tracks the request through all processing steps. This enables easy debugging of request flows and distributed tracing.

### How It Works

1. Client sends request with optional `X-Request-ID` header
2. If not provided, server generates a new UUID
3. Request ID is added to all log entries for that request
4. Request ID is returned in the response `X-Request-ID` header

### Usage Example

#### Client Side

```bash
# Send request with custom request ID
curl -H "X-Request-ID: my-custom-id-123" \
  http://localhost:8080/v1/accept_epoch

# Let server generate request ID
curl http://localhost:8080/v1/accept_epoch
```

#### Tracing Logs

All logs for a specific request can be filtered by request ID:

```bash
# JSON logs
cat server.log | jq 'select(.span.request_id == "550e8400-e29b-41d4-a716-446655440000")'

# Text logs
grep "request_id=550e8400-e29b-41d4-a716-446655440000" server.log
```

## Performance Metrics

### Overview

The API exposes Prometheus-compatible metrics at the `/metrics` endpoint.

### Available Metrics

#### HTTP Request Metrics

- `http_requests_total{method, path}` - Counter of total HTTP requests
- `http_responses_total{method, path, status}` - Counter of HTTP responses by status code
- `http_request_duration_seconds{method, path, status}` - Histogram of request latencies

#### System Metrics

Additional metrics are available based on your deployment environment (CPU, memory, etc.).

### Accessing Metrics

```bash
# View raw metrics
curl http://localhost:8080/metrics

# Example output:
# http_requests_total{method="POST",path="/v1/send_message"} 1234
# http_request_duration_seconds_sum{method="POST",path="/v1/send_message",status="200"} 45.67
# http_request_duration_seconds_count{method="POST",path="/v1/send_message",status="200"} 1234
```

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'cityg-api'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboards

#### Recommended Queries

**Request Rate**:
```promql
rate(http_requests_total[5m])
```

**Error Rate**:
```promql
rate(http_responses_total{status=~"5.."}[5m])
```

**P95 Latency**:
```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

**Request Success Rate**:
```promql
sum(rate(http_responses_total{status=~"2.."}[5m])) / sum(rate(http_responses_total[5m]))
```

## Health Checks

The API provides multiple health check endpoints for different use cases.

### Endpoints

#### 1. Legacy Health Check (Protobuf)

```bash
GET /health
```

Returns protobuf-formatted health status. Maintained for backward compatibility.

#### 2. Liveness Probe

```bash
GET /health/live
```

Simple check that the service is running. Always returns 200 OK if the process is alive.

Response:
```json
{
  "alive": true
}
```

**Use Case**: Kubernetes liveness probe to detect if container needs restart.

#### 3. Readiness Probe

```bash
GET /health/ready
```

Checks if the service is ready to accept traffic. Returns 503 if circuit breaker is open.

Response (ready):
```json
{
  "ready": true
}
```

Response (not ready):
```json
{
  "ready": false,
  "reason": "circuit breaker open"
}
```

**Use Case**: Kubernetes readiness probe to control traffic routing.

#### 4. Detailed Health Check

```bash
GET /health/detailed
```

Comprehensive health status including all subsystems.

Response:
```json
{
  "status": "healthy",
  "timestamp": 1705319445,
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "checks": [
    {
      "name": "system",
      "status": "healthy",
      "message": "Service is running",
      "latency_ms": null
    },
    {
      "name": "circuit_breaker",
      "status": "healthy",
      "message": "state=Closed, failures=0, successes=0",
      "latency_ms": null
    }
  ]
}
```

**Status Values**:
- `healthy`: All systems operational
- `degraded`: Some non-critical issues
- `unhealthy`: Critical issues, returns 503

**Use Case**: Operations dashboard, detailed service status.

### Kubernetes Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cityg-api
spec:
  containers:
  - name: cityg-api
    image: cityg-api:latest
    ports:
    - containerPort: 8080
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 30
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
```

## Resilience Features

### Circuit Breaker

The circuit breaker prevents cascading failures by temporarily blocking requests when error rates are high.

#### States

1. **Closed** (Normal): Requests flow normally
2. **Open** (Failing): Requests fail fast, no backend calls
3. **Half-Open** (Testing): Limited requests allowed to test recovery

#### Configuration

Default settings (in `lib.rs`):
```rust
CircuitBreaker::new(
    5,  // failure_threshold: open after 5 failures
    2,  // success_threshold: close after 2 successes in half-open
    Duration::from_secs(30)  // timeout: try half-open after 30s
)
```

#### Monitoring

Check circuit breaker status:
```bash
curl http://localhost:8080/health/detailed | jq '.checks[] | select(.name == "circuit_breaker")'
```

### Retry Logic with Exponential Backoff

Automatic retry for transient failures with exponential backoff.

#### Retry Conditions

Requests are retried for:
- Network timeouts (408)
- Rate limits (429)
- Server errors (500, 502, 503, 504)

#### Backoff Strategy

- Initial backoff: 100ms
- Maximum retries: 3
- Backoff multiplier: 2x

Example timeline:
1. Initial request fails
2. Wait 100ms, retry
3. Wait 200ms, retry
4. Wait 400ms, retry
5. Return error if still failing

### Offline Message Queue

Messages are queued when network connectivity is lost and automatically sent when connectivity is restored.

#### Features

- **Maximum queue size**: 10,000 messages
- **Automatic retry**: Exponential backoff
- **Message persistence**: In-memory (survives restarts with external persistence)
- **Priority**: FIFO (First In, First Out)

#### Monitoring Queue Status

Queue status is logged periodically:
```
INFO message queued for offline delivery, queue_size=42
INFO network status changed to online, processing queued messages
INFO successfully sent queued message
```

### WebSocket Auto-Reconnect

WebSocket connections include automatic health monitoring and reconnection support.

#### Features

1. **Ping/Pong monitoring**: 30-second interval, 60-second timeout
2. **Lag detection**: Notifies client when lagging
3. **Health signals**: Indicates connection health in notifications
4. **Graceful degradation**: Continues processing on reconnect

#### Client-Side Handling

When you receive a lag notification:
```json
{
  "type": "lag",
  "lagged_messages": 10,
  "recommendation": "consider reconnecting"
}
```

Implement client-side reconnection logic with exponential backoff.

## Production Deployment

### Environment Variables

```bash
# Logging
export LOG_FORMAT=json
export RUST_LOG=info

# Metrics (optional, for custom configs)
export METRICS_PORT=9090

# Server
export BIND_ADDRESS=0.0.0.0:8080
```

### Recommended Setup

1. **Log Aggregation**: Ship JSON logs to ELK, Splunk, or CloudWatch
2. **Metrics Collection**: Configure Prometheus scraping
3. **Alerting**: Set up alerts on key metrics
4. **Dashboards**: Create Grafana dashboards for visualization

### Docker Example

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin cityg-api

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/cityg-api /usr/local/bin/
ENV LOG_FORMAT=json
ENV RUST_LOG=info
EXPOSE 8080
CMD ["cityg-api"]
```

### Docker Compose Example

```yaml
version: '3.8'
services:
  cityg-api:
    image: cityg-api:latest
    ports:
      - "8080:8080"
    environment:
      - LOG_FORMAT=json
      - RUST_LOG=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

volumes:
  prometheus-data:
  grafana-data:
```

## Troubleshooting

### Common Issues

#### 1. High Latency

**Symptom**: P95 latency > 1s

**Investigation**:
```bash
# Check metrics
curl http://localhost:8080/metrics | grep http_request_duration

# Check logs for slow requests
cat server.log | jq 'select(.fields.latency_ms > 1000)'
```

**Solutions**:
- Check database/backend performance
- Increase server resources
- Enable caching
- Review circuit breaker settings

#### 2. Circuit Breaker Keeps Opening

**Symptom**: `/health/ready` returns 503 frequently

**Investigation**:
```bash
# Check detailed health
curl http://localhost:8080/health/detailed | jq '.checks[] | select(.name == "circuit_breaker")'

# Review error logs
cat server.log | jq 'select(.level == "ERROR")'
```

**Solutions**:
- Fix underlying service issues
- Adjust circuit breaker thresholds
- Implement proper error handling
- Add more granular circuit breakers per endpoint

#### 3. WebSocket Disconnections

**Symptom**: Frequent WebSocket reconnections

**Investigation**:
```bash
# Check WebSocket logs
cat server.log | grep -i websocket

# Look for timeout patterns
cat server.log | jq 'select(.fields.message | contains("timeout"))'
```

**Solutions**:
- Adjust ping/pong intervals
- Check network stability
- Increase timeout values
- Implement client-side reconnection with backoff

#### 4. Memory Growth

**Symptom**: Memory usage increases over time

**Investigation**:
```bash
# Check queue size
cat server.log | jq 'select(.fields.queue_size)'

# Monitor metrics
curl http://localhost:8080/health/detailed
```

**Solutions**:
- Review offline queue size limits
- Check for message broadcasting leaks
- Monitor connection count
- Implement connection limits

### Debugging Tools

#### Get Request Flow

```bash
# Follow a specific request through logs
REQUEST_ID="550e8400-e29b-41d4-a716-446655440000"
cat server.log | jq --arg rid "$REQUEST_ID" \
  'select(.span.request_id == $rid) | {time: .timestamp, level, message: .fields.message}'
```

#### Monitor Error Rates

```bash
# Real-time error monitoring
tail -f server.log | jq 'select(.level == "ERROR")'
```

#### Analyze Latency Distribution

```bash
# Get latency percentiles from logs
cat server.log | jq -r 'select(.fields.latency_ms) | .fields.latency_ms' \
  | sort -n \
  | awk '{arr[NR]=$1} END {print "P50:", arr[int(NR*0.5)], "P95:", arr[int(NR*0.95)], "P99:", arr[int(NR*0.99)]}'
```

## Best Practices

### 1. Log Levels in Production

- Use `INFO` as default
- Enable `DEBUG` for specific modules when investigating issues
- Avoid `TRACE` in production (high volume)

### 2. Correlation IDs

- Always propagate `X-Request-ID` across service boundaries
- Include correlation ID in client logs
- Use correlation IDs for cross-service debugging

### 3. Metrics

- Set up alerts on:
  - Error rate > 1%
  - P95 latency > 500ms
  - Circuit breaker open
- Review dashboards regularly
- Archive metrics for capacity planning

### 4. Health Checks

- Use `/health/live` for liveness probes
- Use `/health/ready` for readiness probes
- Monitor `/health/detailed` in dashboards
- Set appropriate timeouts and retries

### 5. Circuit Breakers

- Set thresholds based on SLAs
- Monitor state transitions
- Implement graceful degradation
- Test failure scenarios regularly

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Rust Tracing Crate](https://docs.rs/tracing/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/pwnsdx/cityg/issues
- Documentation: https://github.com/pwnsdx/cityg/docs
