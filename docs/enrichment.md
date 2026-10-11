# Enrichment

[← Back to README](../README.md)

## Kubernetes context

On a Kubernetes node, K-Guard resolves each alert's cgroup back to the owning Pod/container before dispatch. This works even if the process has already exited.

1. The cgroup path is read from `/proc/<pid>/cgroup`. If the PID is gone, K-Guard walks `cgroup_path` looking for a directory whose inode matches the eBPF-reported cgroup ID.
2. The path is parsed (systemd scope naming, cgroupfs raw hex IDs and pod-UID directory naming are all recognized) to extract container ID, runtime and/or Pod UID.
3. That is cross-referenced against a local cache of the Kubelet's `/pods` API to resolve Pod name and namespace.

Enriched alerts carry `container_id`, `pod_name`, `namespace`, `pod_uid` and `runtime`. Alerts from non-Kubernetes processes (or ones that can't be resolved) are dispatched with those fields empty, not held back.

Resolved metadata is cached (LRU, keyed by cgroup ID and PID). The Kubelet pod list refreshes every 30 seconds in the background, plus once synchronously (3s timeout) at startup so the cache is warm before the first events.

Configuration keys are listed in [Configuration](configuration.md#kubernetes-keys). `proc_path`, `cgroup_path` and `kubelet_insecure` are read once at startup; `kubelet_url`, `kubelet_cert_file` and `kubelet_key_file` hot-reload.

## Container escape detection

- **Namespace hopping (`setns`)**: catches processes joining existing host/pod namespaces (e.g. `nsenter` into PID 1 or host mount namespaces).
- **Isolation breakdown (`unshare`)**: flags new namespaces (e.g. `CLONE_NEWNS`, `CLONE_NEWPID`) created from inside tracked container cgroups (`container_cgroups`), catching early-stage escape and privilege escalation.

## DNS interception & IP-to-domain correlation

K-Guard captures DNS traffic and correlates outbound connections (`CONNECT`, `SENDTO`) with resolved domain names in real time, with no external logger.

### Why TC (`clsact`) instead of syscall tracing

Tracing `sendto`/`sendmsg`/`connect` misses DNS traffic because applications use many socket APIs (`sendmsg`, `write`, `io_uring`), and local resolvers (`systemd-resolved`, `dnsmasq`) separate the application PID from the upstream query. Attaching eBPF classifiers to the `clsact` qdisc (`tc_egress_dns` / `tc_ingress_dns`) gives:

- **Full packet coverage**: all UDP/53 traffic across every interface (`eth0`, `veth*`, `lo`), regardless of runtime or syscall.
- **Low overhead**: code runs only on port 53 packets.
- **Deterministic pairing**: queries and answers matched by 16-bit DNS TXID plus ephemeral client port.

> **Limitation:** DNS over TCP, DoH and DoT are not captured by this mechanism.

### Mechanics

1. **Egress capture (`tc_egress_dns`)**: extracts resolver IP, client port, TXID, QNAME and container `cgroup_id`, stored in the `dns_pending_tx` LRU map keyed by `(Resolver IP, Client Port, TXID)`.
2. **Ingress parsing (`tc_ingress_dns`)**: matches responses against `dns_pending_tx`, parses A/AAAA records, emits `EVT_DNS_ANSWER` over the ring buffer, and purges the pending entry.
3. **Two-tier cache in userspace**: `ipScoped` (`{cgroup_id, IP}`) for isolated container matching and `ipFallback` (`{IP}`) for cross-process lookups through local resolver proxies.
4. **Alert enrichment**: egress handlers look up the destination IP in the correlator and add the domain to the alert.
