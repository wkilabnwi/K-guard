# Alert Sinks, Dashboard & Metrics

[← Back to README](../README.md)

## Sinks

| Sink | Description |
|---|---|
| **stdout** | Human-readable, multi-line per alert. Promotes lineage-flagged events and renders a `Process Lineage Trace` showing root ancestors and parent chains |
| **syslog** | JSON body, severity mapped to a syslog level |
| **webhook** | POSTs `{ "text": <summary>, "alert": <Alert> }` as JSON |
| **slack** | POSTs formatted Markdown messages to Slack or Discord webhooks (`sinks.slack_webhook_url`) |
| **store** | Append-only, date-rotated JSON-Lines files. Backs the dashboard and its `/api/alerts` endpoint |
| **metrics** | Prometheus text exposition at `/metrics` |

Each sink has its own bounded queue and delivery goroutine, so a slow or stuck sink only drops alerts for itself. It never blocks the ring buffer reader or other sinks.

## Prometheus metrics

`kguard_events_total`, `kguard_rule_hits_total`, `kguard_kills_total`, `kguard_kill_errors_total`, `kguard_blocks_total`, `kguard_ringbuf_drops_total`, `kguard_sink_errors_total`, `kguard_hash_check_errors_total`

## Dashboard & metrics auth

The dashboard (`sinks.dashboard_listen_addr`) and metrics (`sinks.metrics_listen_addr`) servers support optional bearer-token auth. If no token is set, the server still starts but logs a warning and serves **without authentication**. That is fine for `127.0.0.1`-only binding plus SSH port-forwarding, but risky if the address is reachable from elsewhere.

Via config:

```json
"sinks": {
  "dashboard_auth_token": "<random token>",
  "metrics_auth_token": "<random token>"
}
```

Or, preferably, via environment variables (kept out of the plaintext config file). They take precedence if both are set:

```bash
export KGUARD_DASHBOARD_TOKEN="$(openssl rand -hex 32)"
export KGUARD_METRICS_TOKEN="$(openssl rand -hex 32)"
```

When testing with `sudo`, remember it resets the environment by default. Use `sudo -E` to keep your tokens, or source them from a file readable by root.

## Health endpoint

`/healthz` is served alongside `/metrics`, **unauthenticated**, for liveness probes. It reports uptime, active sensors, LSM status, build revision, and seconds since the last event was read from the ring buffer.

## Structured logging

All daemon operations emit structured `slog` key-value logs tagged with a `component` attribute: `engine`, `ebpf`, `trust`, `k8s`, `config`, `dashboard`, `alert`, `audit`.
