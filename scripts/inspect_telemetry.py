import os
import struct

RECORD_SIZE = 56
# Format: 6 uint64 (Q) + 2 uint32 (I) = 56 bytes 
# ts, p_dev, p_ino, c_dev, c_ino, cgroup_id, event_type, uid
STRUCT_FORMAT = '<QQQQQQII'

bin_path = "/var/lib/kguard/telemetry.bin"

if not os.path.exists(bin_path) or os.path.getsize(bin_path) == 0:
    print("No telemetry data found yet or file is empty.")
    exit(1)

file_size = os.path.getsize(bin_path)
total_records = file_size // RECORD_SIZE
print(f"Loaded {total_records} records ({file_size} bytes).\n")

def resolve_ino(ino):
    if ino == 0:
        return "[SYSTEM / ROOT_ANCESTOR]"
    for search_dir in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]:
        try:
            for entry in os.scandir(search_dir):
                if entry.stat(follow_symlinks=False).st_ino == ino:
                    return entry.path
        except Exception:
            continue
    return f"ino:{ino}"

transitions = {}

with open(bin_path, "rb") as f:
    while chunk := f.read(RECORD_SIZE):
        if len(chunk) < RECORD_SIZE:
            break
        ts, p_dev, p_ino, c_dev, c_ino, cgroup_id, evt_type, uid = struct.unpack(STRUCT_FORMAT, chunk)
        
        key = (uid, p_ino, c_ino)
        transitions[key] = transitions.get(key, 0) + 1

print(f"{'UID':<6} {'Parent Process':<30} -> {'Child Process':<30} {'Count'}")
print("-" * 75)
for (uid, p_ino, c_ino), count in transitions.items():
    p_name = resolve_ino(p_ino)
    c_name = resolve_ino(c_ino)
    print(f"{uid:<6} {p_name:<30} -> {c_name:<30} {count}")