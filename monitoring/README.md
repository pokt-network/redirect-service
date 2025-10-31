# Taiji Monitoring

This directory contains production-ready monitoring configurations for Taiji reverse proxy.

## Contents

### Grafana Dashboard (`grafana/taiji-dashboard.yaml`)

A comprehensive Grafana dashboard ConfigMap with support for:

- **Multi-backend filtering**: Filter metrics by subdomain and backend
- **Service health overview**: Status, request rate, latency, error rate
- **Traffic analysis**:
  - Request rate by subdomain and backend
  - Backend traffic ranking table
  - Status code distribution
- **Performance metrics**:
  - Latency percentiles (P50, P95, P99) by subdomain and backend
  - Backend-specific P99 latency comparison
- **Backend health**:
  - 5xx error rate by backend
  - 502 errors (backend connectivity issues)
- **Configuration monitoring**:
  - Rule status (active/inactive)
  - CSV reload attempts and errors

**Key Features:**
- Template variables for subdomain and backend filtering
- Color-coded thresholds for quick health assessment
- Table views for ranking and analysis
- 30-second auto-refresh

### Prometheus Alerts (`prometheus/taiji-alerts.yaml`)

PrometheusRule with comprehensive alerting:

#### Critical Alerts
- `TaijiSubdomainHighServerErrors` - Subdomain has >5% 5xx errors
- `TaijiBackendHighErrorRate` - Backend has >10% error rate
- `TaijiBackendMany502Errors` - Backend generating many 502s (likely down)
- `TaijiServiceDown` - Instance is down
- `TaijiServiceCompleteOutage` - All instances down
- `TaijiSubdomainBackendDown` - Subdomain backend completely failing
- `TaijiCSVReloadFailures` - Configuration reload errors

#### Warning Alerts
- `TaijiSubdomainElevatedServerErrors` - Subdomain has >1% 5xx errors
- `TaijiBackendElevatedErrorRate` - Backend has >3% error rate
- `TaijiHighLatency` - Overall P99 latency >1s
- `TaijiBackendHighLatency` - Backend P99 latency >2s
- `TaijiSubdomainHigh404Rate` - High 404 rate (misconfiguration)
- `TaijiWatcherRestarts` - File watcher restarting frequently
- `TaijiLowTraffic` - Unusually low request rate
- `TaijiUnevenBackendLoad` - Load distribution imbalance (5x difference)
- `TaijiBackendSlowResponse` - Backend consistently slow (P50 >500ms)

**Key Improvements:**
- ✅ **Fixed formatting**: Alert values now show "0.0037 requests per second (0.22 requests/min)" instead of confusing "3.704m"
- ✅ **Backend-specific alerts**: Monitor individual backend health and performance
- ✅ **Load distribution monitoring**: Detect round-robin issues
- ✅ **Better descriptions**: Clear, actionable alert messages

## Deployment

### Prerequisites

- Kubernetes cluster with Prometheus Operator (kube-prometheus-stack)
- Grafana with dashboard sidecar enabled
- Taiji deployed with `job="taiji"` in ServiceMonitor

### Installation

```bash
# Apply Grafana dashboard
kubectl apply -f grafana/taiji-dashboard.yaml

# Apply Prometheus alerts
kubectl apply -f prometheus/taiji-alerts.yaml
```

### Verification

```bash
# Check if dashboard ConfigMap is created
kubectl get configmap taiji-dashboard -n monitoring

# Check if PrometheusRule is created
kubectl get prometheusrule taiji-alerts -n monitoring

# Verify Grafana picked up the dashboard
# (Check Grafana UI under Dashboards)

# Verify Prometheus loaded the alerts
kubectl port-forward -n monitoring svc/kps-kube-prometheus-sta-prometheus 9090:9090
# Open http://localhost:9090/alerts and search for "Taiji"
```

## Customization

### Adjusting Alert Thresholds

Edit `prometheus/taiji-alerts.yaml` and modify the `expr` field thresholds:

```yaml
# Example: Change high error rate from 10% to 15%
- alert: TaijiBackendHighErrorRate
  expr: |
    (
      sum by (subdomain, backend) (rate(proxy_requests_total{job="taiji",status_code=~"5.."}[5m]))
      / sum by (subdomain, backend) (rate(proxy_requests_total{job="taiji"}[5m]))
    ) > 0.15  # Changed from 0.10
```

### Customizing Dashboard

The dashboard JSON is embedded in the ConfigMap. To modify:

1. Import the dashboard into Grafana
2. Make your changes in the Grafana UI
3. Export the JSON
4. Replace the `taiji-dashboard.json` content in the YAML file

### Changing Job Label

If your ServiceMonitor uses a different job label, update both files:

```bash
# Replace job="taiji" with your job name
sed -i 's/job="taiji"/job="your-job-name"/g' prometheus/taiji-alerts.yaml
```

## Metrics Reference

All metrics used in dashboard and alerts:

- `up{job="taiji"}` - Service availability
- `proxy_rules_total` - Total number of backends
- `proxy_requests_total{subdomain, backend, status_code}` - Request counter
- `proxy_request_duration_seconds_bucket{subdomain, backend, le}` - Latency histogram
- `proxy_last_request_timestamp_seconds{subdomain, backend}` - Last request time
- `proxy_rule_active{subdomain}` - Rule status
- `proxy_csv_reload_total` - CSV reload attempts
- `proxy_csv_reload_errors_total` - CSV reload errors
- `proxy_watcher_restarts_total` - File watcher restarts

## Troubleshooting

### Dashboard not showing up in Grafana

1. Check if ConfigMap has the correct label:
   ```bash
   kubectl get cm taiji-dashboard -n monitoring -o jsonpath='{.metadata.labels}'
   ```
   Should include: `grafana_dashboard: "1"`

2. Check Grafana sidecar logs:
   ```bash
   kubectl logs -n monitoring deployment/kps-grafana -c grafana-sc-dashboard
   ```

### Alerts not firing in Prometheus

1. Check if PrometheusRule is valid:
   ```bash
   kubectl describe prometheusrule taiji-alerts -n monitoring
   ```

2. Check Prometheus logs for parsing errors:
   ```bash
   kubectl logs -n monitoring prometheus-kps-kube-prometheus-sta-prometheus-0
   ```

3. Verify metrics are being scraped:
   ```bash
   # Port-forward and check targets
   kubectl port-forward -n monitoring svc/kps-kube-prometheus-sta-prometheus 9090:9090
   # Open http://localhost:9090/targets
   ```

## Integration with PagerDuty/Slack

To route alerts to PagerDuty or Slack, configure Alertmanager:

```yaml
route:
  group_by: ['alertname', 'cluster', 'service']
  routes:
    - match:
        service: taiji
        severity: critical
      receiver: pagerduty-critical
    - match:
        service: taiji
        severity: warning
      receiver: slack-warnings
```

Refer to the Alertmanager documentation for detailed receiver configuration.
