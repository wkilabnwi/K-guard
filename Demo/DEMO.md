# K-Guard Demo

K-Guard is a host-based intrusion prevention system built on eBPF: tracepoint sensors for
detection, and an LSM (`bprm_check_security`) hook for real pre-exec prevention. This walks
through a few live scenarios, from harmless-looking to actively malicious, showing what
K-Guard sees and does at each stage.

---

## 1. Dashboard overview

The built-in web dashboard (`sinks.dashboard_listen_addr` in config) shows live sensor status,
whether LSM enforcement is active, and a scrollable history of every alert K-Guard has fired.

![K-Guard dashboard](docs/UI_Web.png)

Enforcement is `ACTIVE` here : the LSM pre-exec block hook attached successfully, so K-Guard
isn't just detecting-and-killing, it's actually preventing execution for anything on the
block-list.

---

## 2. Suspicious-path exec + connect correlation

**Scenario:** a binary copied into `/tmp` (a classic dropped-payload location) then makes an
outbound connection individually unremarkable, but the *combination* in a short window is a
strong signal of a reverse shell / C2 beacon.

```bash
cp /usr/bin/python3 /tmp/python3-runner
chmod +x /tmp/python3-runner
/tmp/python3-runner /tmp/conn_test.py   # connects out to 1.1.1.1:80
```

![Setting up the suspicious-path exec + connect](docs/Correlation_cmds.png)

K-Guard's correlator (`internal/processor/correlate.go`) remembers that this PID exec'd from a
suspicious path, and when the same PID opens a connection shortly after, escalates the alert
from `low` to `high` severity automatically:

![Correlated alert: exec from /tmp followed by outbound connect](docs/Correlation_Alert.png)

---

## 3. Pre-exec block: `nc`

**Scenario:** an attempt to launch `nc` (netcat) : commonly used for reverse shells/listeners 
where the exact path is on K-Guard's LSM block-list.

```bash
sudo /usr/bin/nc -l -p 4444
```

![Attempting to run nc](docs/nc_cmd.png)

Because `/usr/bin/nc` is synced into the in-kernel `blocked_paths` map, the LSM hook denies the
`execve()` outright, the binary never runs at all, not even for a moment:

![nc blocked pre-flight by the LSM hook](docs/nc_kill.png)

Note the alert type: `EXEC_BLOCKED`, not `KILL`, there's no process to kill, since it was never
allowed to start.

---

## 4. Detect-and-kill fallback: `tcpdump` from `/tmp`

**Scenario:** a raw-socket sniffer, copied to `/tmp` and run outside the trusted admin
allowlist, this rule isn't on the exact-path LSM block-list, so it's caught by the tracepoint
sensor path instead (post-exec) and killed as a fallback response.

```bash
mkdir -p /tmp/tools
cp "$(which tcpdump)" /tmp/tools/tcpdump
sudo /tmp/tools/tcpdump -i lo -c 1
```

![Copying and running tcpdump from /tmp](docs/tcpdump_cmds.png)

K-Guard fires two alerts here: first a medium-severity `ALERT` for running a raw-socket tool
outside the allowlist, then a high-severity `KILL` for executing from a suspicious path and
the process is terminated (`Killed`, visible in the shell output above):

![tcpdump alerted and killed](docs/tcpdump_Alert_KATF.png)

---

## 5. Crypto miner detection: `xmrig`

**Scenario:** a binary named after a known cryptominer (`xmrig`), regardless of where it's
placed, this rule matches on basename/pattern with no suspicious-path requirement, since
miner binaries are unwanted anywhere on the host.

```bash
cp /bin/sleep /tmp/xmrig
chmod +x /tmp/xmrig
/tmp/xmrig 30 &
```

![Launching a binary named xmrig](docs/xmrig_cmd.png)

K-Guard matches the rule immediately and sends `SIGKILL`:

![xmrig detected and terminated](docs/xmrig_KATF.png)

---

## Summary

| Scenario | Detection path | Response |
|---|---|---|
| `/tmp` exec -> outbound connect | Tracepoint + correlator | `ALERT` (escalated severity) |
| `nc` (exact-path block rule) | LSM pre-exec hook | `BLOCK` : never executes |
| `tcpdump` from `/tmp` | Tracepoint (post-exec) | `ALERT` then `KILL` |
| `xmrig` (any path) | Tracepoint (post-exec) | `KILL` |

The block-vs-kill distinction is the core design point of K-Guard: exact-path rules get synced
into the kernel and are prevented before they ever run, while everything else (substring/prefix
rules, basename rules like the miner match above) is caught immediately after the fact via the
tracepoint sensors and a best-effort kill.