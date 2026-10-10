# ML Telemetry Pipeline

[← Back to README](../README.md)

An asynchronous, non-blocking telemetry tap for behavioral baselining and ML model training. This is the first step toward an automated ML-supported anomaly prevention system.

## Design

- **Tamper-proof identification**: trains on filesystem `(dev, ino)` integer pairs (`parent_exe_ino` → `exe_ino`) rather than spoofable process names (`comm` or path strings). Raw 64-bit integers also speed up offline graph generation and training.
- **Zero-allocation binary storage**: events are written as raw 56-byte little-endian fixed structs (`binary.Write`) to `/var/lib/kguard/telemetry.bin`, avoiding string allocation, JSON encoding and CPU overhead in the event loop.
- **Non-blocking channel tap**: telemetry flows over a buffered Go channel (`telemetryChan`). If the consumer falls behind, samples are dropped so core enforcement latency is preserved.

## Inspecting the data

`/var/lib/kguard/telemetry.bin` is written with root-only permissions (`0600`), so run the script with `sudo`:

```bash
sudo python3 scripts/inspect_telemetry.py
```

The script unpacks the 56-byte records, aggregates parent-child execution frequencies, and resolves inodes back to binary paths on disk.

> It is a quick verification tool only. Some inodes may show as `ino:XXXXX` because it scans just `/bin`, `/usr/bin`, `/sbin` and `/usr/sbin`, with no system-wide or container filesystem resolution.
