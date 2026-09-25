#!/usr/bin/env python
# OFFLINE_COLLECTOR_VERSION: v2026-08-22-opt-1
from __future__ import print_function
import subprocess
import re
import os
import json
import time
from concurrent.futures import ThreadPoolExecutor


def run_cmd(cmd, timeout_sec=60):
    try:
        env_setup = (
            "export PATH=/usr/local/nutanix/bin:/home/nutanix/cluster/bin:/home/nutanix/bin:$PATH; "
            "source /etc/profile >/dev/null 2>&1; "
            "source ~/.bashrc >/dev/null 2>&1; "
        )
        full_cmd = env_setup + cmd
        p = subprocess.Popen(
            full_cmd,
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = p.communicate(timeout=timeout_sec)
        res = ""
        if out:
            res += out.decode("utf-8", "ignore")
        if err:
            err_str = err.decode("utf-8", "ignore")
            if "Using curator master" not in err_str:
                res += "\n[STDERR]\n" + err_str
        return res
    except subprocess.TimeoutExpired:
        p.kill()
        return "[TIMEOUT] Command expired after %ss: %s" % (timeout_sec, cmd)
    except Exception as e:
        return "[ERROR] " + str(e)


def run_binary(binary_cmd, timeout_sec=90):
    parts = binary_cmd.split(" ", 1)
    bin_name = parts[0]
    args = " " + parts[1] if len(parts) > 1 else ""
    possible_paths = [
        "/home/nutanix/cluster/bin/" + bin_name,
        "/usr/local/nutanix/bin/" + bin_name,
        "/home/nutanix/bin/" + bin_name,
        bin_name,
    ]
    for path in possible_paths:
        full_cmd = path + args
        res = run_cmd(full_cmd, timeout_sec=timeout_sec)
        clean_res = res.strip()
        if (
            clean_res
            and "command not found" not in clean_res
            and "No such file" not in clean_res
            and not clean_res.startswith("[STDERR]")
        ):
            return res
    return ""


def get_bool_env(name, default=False):
    v = os.environ.get(name, "")
    if not v:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def get_int_env(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def run_batch_with_retry(batch_idx, ids_chunk, cmd_prefix, timeout_sec=240, retry_chunk_size=40):
    if not ids_chunk:
        return batch_idx, ""
    cmd = cmd_prefix + ",".join(ids_chunk)
    out = run_cmd(cmd, timeout_sec=timeout_sec)
    out_l = out.lower()
    has_failure = ("[timeout]" in out_l) or ("[error]" in out_l)
    if (not has_failure) or len(ids_chunk) <= retry_chunk_size:
        return batch_idx, out

    # Retry once by splitting into smaller sub-batches.
    sub_rows = []
    for i in range(0, len(ids_chunk), retry_chunk_size):
        sub = ids_chunk[i:i + retry_chunk_size]
        sub_cmd = cmd_prefix + ",".join(sub)
        sub_out = run_cmd(sub_cmd, timeout_sec=timeout_sec)
        sub_rows.append(sub_out)
    return batch_idx, "\n".join(sub_rows)


def run_chunked_parallel(ids, chunk_size, max_workers, cmd_prefix, timeout_sec=240, retry_chunk_size=40):
    if not ids:
        return ""
    batches = [(i // chunk_size + 1, ids[i:i + chunk_size]) for i in range(0, len(ids), chunk_size)]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(
            lambda t: run_batch_with_retry(
                t[0], t[1], cmd_prefix,
                timeout_sec=timeout_sec,
                retry_chunk_size=retry_chunk_size
            ),
            batches
        ))
    results.sort(key=lambda x: x[0])
    return "\n".join(r[1] for r in results if r[1])


FAST_MODE = get_bool_env("FAST_MODE", False)
MAX_CONTAINERS = get_int_env("MAX_CONTAINERS", 0)
CURATOR_WORKERS = max(1, get_int_env("CURATOR_WORKERS", 4))
CURATOR_VDISK_CHUNK = max(1, get_int_env("CURATOR_VDISK_CHUNK", 80 if FAST_MODE else 120))
CURATOR_CHAIN_CHUNK = max(1, get_int_env("CURATOR_CHAIN_CHUNK", 80 if FAST_MODE else 120))
CURATOR_RETRY_CHUNK = max(1, get_int_env("CURATOR_RETRY_CHUNK", 30 if FAST_MODE else 40))
collector_timing = {}

print("[1/7] Collecting core NCLI + vdisk metadata...")
t0 = time.time()
ncli_ctr = run_cmd("ncli container ls", timeout_sec=90)
ncli_vm = run_cmd("ncli vm ls", timeout_sec=120)
ncli_vg = run_cmd("ncli volume-group ls", timeout_sec=120)
ncli_sp = run_cmd("ncli storagepool ls", timeout_sec=60)
vdisk_cfg = run_binary("vdisk_config_printer", timeout_sec=120)
collector_timing["core_query_sec"] = round(time.time() - t0, 3)

print("[2/7] Preparing container metadata for batching...")
container_names = []
for m in re.finditer(r"^\s*Name\s*:\s*([^\n]+)", ncli_ctr, re.MULTILINE):
    nm = m.group(1).strip()
    if nm and nm not in container_names:
        container_names.append(nm)
if MAX_CONTAINERS > 0:
    container_names = container_names[:MAX_CONTAINERS]
collector_timing["nfs_ls_sec"] = 0.0

print("[3/7] Parsing IDs for curator batching...")
raw_vdisk_ids = sorted(
    set(re.findall(r"^\s*vdisk_id\s*:\s*(\d+)", vdisk_cfg, re.MULTILINE)),
    key=lambda x: int(x),
)
raw_chain_ids = sorted(
    set(re.findall(r"^\s*chain_id\s*:\s*\"([0-9a-fA-F-]{36})\"", vdisk_cfg, re.MULTILINE))
)


def run_curator_vdisk_usage(vdisk_ids, chunk_size=120):
    return run_chunked_parallel(
        vdisk_ids,
        chunk_size=chunk_size,
        max_workers=CURATOR_WORKERS,
        cmd_prefix="curator_cli get_vdisk_usage lookup_vdisk_ids=",
        timeout_sec=240 if not FAST_MODE else 180,
        retry_chunk_size=CURATOR_RETRY_CHUNK
    )


def run_curator_chain_usage(chain_ids, chunk_size=120):
    return run_chunked_parallel(
        chain_ids,
        chunk_size=chunk_size,
        max_workers=CURATOR_WORKERS,
        cmd_prefix="curator_cli get_vdisk_chain_usage lookup_chain_ids=",
        timeout_sec=240 if not FAST_MODE else 180,
        retry_chunk_size=CURATOR_RETRY_CHUNK
    )


print("[4/7] Querying curator vdisk usage...")
t0 = time.time()
curator_out = run_curator_vdisk_usage(raw_vdisk_ids, chunk_size=CURATOR_VDISK_CHUNK)
collector_timing["curator_vdisk_sec"] = round(time.time() - t0, 3)
print("[5/7] Querying curator chain usage...")
t0 = time.time()
curator_chain_out = run_curator_chain_usage(raw_chain_ids, chunk_size=CURATOR_CHAIN_CHUNK)
collector_timing["curator_chain_sec"] = round(time.time() - t0, 3)
print("[5b/7] Querying curator garbage report...")
t0 = time.time()
curator_garbage_out = run_binary("curator_cli display_garbage_report", timeout_sec=180)
collector_timing["curator_garbage_sec"] = round(time.time() - t0, 3)
collector_timing["container_count"] = len(container_names)
collector_timing["vdisk_count"] = len(raw_vdisk_ids)
collector_timing["chain_count"] = len(raw_chain_ids)
collector_timing["fast_mode"] = FAST_MODE
collector_timing["skip_nfs_ls"] = True
collector_timing["collector_workers"] = {"curator": CURATOR_WORKERS}
collector_timing["collector_chunk"] = {"vdisk": CURATOR_VDISK_CHUNK, "chain": CURATOR_CHAIN_CHUNK, "retry": CURATOR_RETRY_CHUNK}

out_filename = "vdisk_sniffer_offline.log"
print("[6/7] Writing output to %s..." % out_filename)
with open(out_filename, "w") as f:
    f.write("===VDISK_CFG_START===\n" + vdisk_cfg + "\n")
    f.write("===NCLI_SP_START===\n" + ncli_sp + "\n")
    f.write("===NCLI_VM_START===\n" + ncli_vm + "\n")
    f.write("===NCLI_VG_START===\n" + ncli_vg + "\n")
    f.write("===NCLI_CTR_START===\n" + ncli_ctr + "\n")
    f.write("===CURATOR_START===\n" + curator_out + "\n")
    f.write("===CURATOR_CHAIN_USAGE_START===\n" + curator_chain_out + "\n")
    f.write("===CURATOR_GARBAGE_START===\n" + curator_garbage_out + "\n")
    f.write("===COLLECTOR_TIMING_START===\n" + json.dumps(collector_timing) + "\n")

print("[7/7] DONE: upload 'vdisk_sniffer_offline.log' to VDisk Sniffer.")
