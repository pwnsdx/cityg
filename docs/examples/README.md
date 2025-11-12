# City-G Configuration Examples

This directory contains production-ready configuration examples for deploying City-G in various environments.

## 📁 Contents

### Docker
- **[docker-compose.yml](./docker-compose.yml)** - Complete Docker Compose stack
  - City-G API server
  - Prometheus metrics collection
  - Grafana dashboards
  - Persistent volumes for journal storage

### Kubernetes
- **[kubernetes-deployment.yml](./kubernetes-deployment.yml)** - Production K8s deployment
  - High-availability deployment (3 replicas)
  - Horizontal Pod Autoscaler
  - ConfigMap for configuration
  - PersistentVolumeClaim for journal
  - ServiceMonitor for Prometheus Operator

### Monitoring
- **[prometheus.yml](./prometheus.yml)** - Prometheus scrape configuration
  - Metrics collection from City-G API
  - Example alerting rules
  - Self-monitoring

### Configuration
- **[config-production.toml](./config-production.toml)** - Production TOML config
  - Recommended production settings
  - Performance tuning notes
  - Security considerations

## 🚀 Quick Start

### Docker Compose

```bash
# Copy and customize configuration
cp docs/examples/docker-compose.yml .
cp docs/examples/prometheus.yml .

# Start the stack
docker-compose up -d

# View logs
docker-compose logs -f cityg-api

# Access services
# - City-G API: http://localhost:8080
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/admin)
```

### Kubernetes

```bash
# Apply configuration
kubectl apply -f docs/examples/kubernetes-deployment.yml

# Check deployment status
kubectl get pods -n cityg
kubectl get svc -n cityg

# View logs
kubectl logs -n cityg -l app=cityg-api --tail=100 -f

# Access API (after LoadBalancer assigns external IP)
kubectl get svc -n cityg cityg-api-service
```

### Standalone with Custom Config

```bash
# Copy production config
cp docs/examples/config-production.toml cityg.toml

# Edit configuration
vim cityg.toml

# Run with custom config
cargo run --release --bin cityg-api -- --config cityg.toml
```

## 📊 Monitoring

### Prometheus Metrics

Access Prometheus at `http://localhost:9090` and run queries:

```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_responses_total{status=~"5.."}[5m])

# P95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Window utilization
mhw_current_heads / mhw_max_heads
```

### Grafana Dashboards

1. Access Grafana at `http://localhost:3000`
2. Login with `admin/admin`
3. Add Prometheus data source: `http://prometheus:9090`
4. Import dashboard or create custom panels

**Recommended panels:**
- Request rate (by endpoint)
- Error rate (by status code)
- Latency percentiles (P50, P95, P99)
- Window utilization
- Circuit breaker state
- Active WebSocket connections

## ⚙️ Configuration Tuning

**For detailed configuration tuning guidance**, see:
- **[Configuration Guide](../configuration.md)** - Complete configuration reference
- **[config-production.toml](./config-production.toml)** - Production-ready example with tuning notes

## 🔐 Security Checklist

- [ ] Enable TLS (use reverse proxy like nginx)
- [ ] Set `RUST_LOG=info` (not debug/trace in production)
- [ ] Run as non-root user
- [ ] Enable firewall (only necessary ports)
- [ ] Set resource limits (CPU, memory)
- [ ] Enable journal for crash recovery
- [ ] Back up journal regularly
- [ ] Verify server-blindness: `./scripts/verify_no_secrets.sh`
- [ ] Monitor metrics and set up alerts
- [ ] Use strong random values for session keys

## 📈 Performance Tuning

### CPU-Bound (Proof Generation)

- Increase CPU limits in Kubernetes
- Scale horizontally (more replicas)
- Consider dedicated validation nodes

### Memory-Bound (Large Rosters)

- Increase memory limits
- Tune `members_page_limit` and caching TTLs
- Monitor window utilization

### Network-Bound (High Message Volume)

- Increase `websocket_capacity`
- Use faster network storage for journal
- Enable HTTP/2 (via reverse proxy)

## 🐛 Troubleshooting

**Quick Docker/Kubernetes Checks:**

```bash
# Check container logs
docker-compose logs cityg-api
kubectl logs -n cityg -l app=cityg-api --tail=100

# Check container is running
docker-compose ps
kubectl get pods -n cityg

# Verify port accessibility
curl http://localhost:8080/health/live
```

**For complete troubleshooting guides**, see:
- **[Troubleshooting Guide](../TROUBLESHOOTING.md)** - Comprehensive solutions for all common issues
- **[Observability Guide](../OBSERVABILITY.md)** - Monitoring and debugging

## 📚 Additional Resources

- [Configuration Guide](../configuration.md) - Complete configuration reference
- [Observability Guide](../OBSERVABILITY.md) - Monitoring and logging
- [Troubleshooting Guide](../TROUBLESHOOTING.md) - Common issues and solutions
- [Deployment Guide](../protocol/14-deployment-guide.md) - Production deployment best practices

## 🤝 Contributing

Found an issue with these examples or have improvements? Please open an issue or PR!

---

**Last Updated**: 2025-11-12
**Version**: 0.1.0
