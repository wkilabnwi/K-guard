# Identity-Based Trust

[← Back to README](../README.md)

Applies to `protected_comms`, `ignored_connect_comms` and `allowed_ptrace_attaches`.

These lists used to match the kernel's `comm` field, which is short and trivially spoofable: any process can rewrite its own `comm` (e.g. `prctl(PR_SET_NAME)`), and the kernel sets it from whatever name a binary was exec'd under. K-Guard now resolves each configured **absolute path** to the real file it points at and matches on that.

## How it works

- Each path is opened via `O_PATH` (`O_PATH | O_NONBLOCK | O_CLOEXEC`), kept pinned via a held file descriptor (not repeatedly re-`stat`'d), and identified by its `(device, inode)` pair, the same identity the kernel's VFS uses.
- **Integrity check before pinning**: K-Guard refuses to trust any file that is not owned by root (`uid == 0`) or is group/world-writable (`mode & 0022 != 0`).
- Config validation rejects any entry that isn't an absolute path.

## Per-list enforcement

| List | Where it's checked |
|---|---|
| `allowed_ptrace_attaches` | Entirely in-kernel. `ptrace_access_check` resolves the *calling* process's `mm->exe_file` and looks it up in a kernel map keyed by `(dev, ino)` |
| `ignored_connect_comms` | Every event header carries the emitting process's resolved exe identity, checked in userspace before the rule engine |
| `protected_comms` | At the moment of a kill attempt, by re-resolving the *live* pid's current `/proc/<pid>/exe`, so a rename or config change between event and kill can't be exploited |

## Device number normalization

The raw `dev_t` from `stat(2)` in userspace differs from what the kernel exposes via `inode->i_sb->s_dev`. K-Guard normalizes by decoding major/minor and re-encoding in the kernel layout before comparing.

## Reload behavior

All three lists hot-reload via `SIGHUP` or the 5-second poll. If a pinned target changes on disk without a reload, K-Guard keeps enforcing against the old identity until the next reload re-resolves it. See the symlink guidance in [Configuration](configuration.md#validation).
