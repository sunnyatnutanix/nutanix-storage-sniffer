import paramiko
import logging
import os
import re
import time

logger = logging.getLogger("vdisk_sniffer.collector")

class CVMCollector:
    def __init__(self, host: str, username: str = "nutanix", password: str = "", port: int = 22):
        self.host = host.strip()
        self.username = username.strip()
        self.password = password
        self.port = port

    def fetch_all_cvm_data(self, progress_callback=None) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        cvm_python_script = r"""
from __future__ import print_function
import subprocess, re, sys, time, json
import os
from concurrent.futures import ThreadPoolExecutor

collector_timing = {}

def emit_progress(step_num, message):
    print("===PROGRESS:%s/7:%s===" % (step_num, message))
    sys.stdout.flush()

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
            executable='/bin/bash',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = p.communicate(timeout=timeout_sec)
        res = ""
        if out:
            res += out.decode('utf-8', 'ignore') if hasattr(out, 'decode') else str(out)
        if err:
            err_str = err.decode('utf-8', 'ignore') if hasattr(err, 'decode') else str(err)
            if "Using curator master" not in err_str:
                res += "\n[STDERR]\n" + err_str
        return res
    except subprocess.TimeoutExpired:
        p.kill()
        return "[TIMEOUT] Command expired after " + str(timeout_sec) + "s: " + cmd
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
        bin_name
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

    sub_rows = []
    for i in range(0, len(ids_chunk), retry_chunk_size):
        sub = ids_chunk[i:i+retry_chunk_size]
        sub_cmd = cmd_prefix + ",".join(sub)
        sub_out = run_cmd(sub_cmd, timeout_sec=timeout_sec)
        sub_rows.append(sub_out)
    return batch_idx, "\n".join(sub_rows)

def run_chunked_parallel(ids, chunk_size, max_workers, cmd_prefix, timeout_sec=240, retry_chunk_size=40):
    if not ids:
        return ""
    batches = [(i // chunk_size + 1, ids[i:i+chunk_size]) for i in range(0, len(ids), chunk_size)]
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
SKIP_NFS_LS = get_bool_env("SKIP_NFS_LS", False)
MAX_CONTAINERS = get_int_env("MAX_CONTAINERS", 0)
NFS_WORKERS = max(1, get_int_env("NFS_WORKERS", 4))
CURATOR_WORKERS = max(1, get_int_env("CURATOR_WORKERS", 4))
CURATOR_VDISK_CHUNK = max(1, get_int_env("CURATOR_VDISK_CHUNK", 80 if FAST_MODE else 120))
CURATOR_CHAIN_CHUNK = max(1, get_int_env("CURATOR_CHAIN_CHUNK", 80 if FAST_MODE else 120))
CURATOR_RETRY_CHUNK = max(1, get_int_env("CURATOR_RETRY_CHUNK", 30 if FAST_MODE else 40))

t0 = time.time()
emit_progress(1, "Collecting core NCLI + vdisk metadata...")
ncli_ctr = run_cmd("ncli container ls", timeout_sec=90)
ncli_vm = run_cmd("ncli vm ls", timeout_sec=120)
ncli_vg = run_cmd("ncli volume-group ls", timeout_sec=120)
ncli_sp = run_cmd("ncli storagepool ls", timeout_sec=60)
vdisk_cfg = run_binary("vdisk_config_printer", timeout_sec=120)
collector_timing["core_query_sec"] = round(time.time() - t0, 3)

# Per-container nfs_ls extraction.
emit_progress(2, "Collecting per-container nfs_ls sections...")
container_names = []
for m in re.finditer(r'^\s*Name\s*:\s*([^\n]+)', ncli_ctr, re.MULTILINE):
    nm = m.group(1).strip()
    if nm and nm not in container_names:
        container_names.append(nm)

nfs_ls_sections = []
if MAX_CONTAINERS > 0:
    container_names = container_names[:MAX_CONTAINERS]
if SKIP_NFS_LS:
    nfs_ls_out = ""
    collector_timing["nfs_ls_sec"] = 0.0
else:
    t0 = time.time()
    def collect_nfs(cname):
        nfs_cmd = "nfs_ls -liaRh '/%s'" % cname.replace("'", "'\\''")
        nfs_out = run_cmd(nfs_cmd, timeout_sec=120 if FAST_MODE else 180)
        return cname, "###CONTAINER:%s\n%s\n###CONTAINER_END###" % (cname, nfs_out)

    with ThreadPoolExecutor(max_workers=NFS_WORKERS) as ex:
        nfs_rows = list(ex.map(collect_nfs, container_names))
    nfs_rows.sort(key=lambda x: x[0])
    nfs_ls_out = "\n".join([r[1] for r in nfs_rows])
    collector_timing["nfs_ls_sec"] = round(time.time() - t0, 3)

raw_vdisk_ids = sorted(set(re.findall(r'^\s*vdisk_id\s*:\s*(\d+)', vdisk_cfg, re.MULTILINE)), key=lambda x: int(x))
raw_chain_ids = sorted(set(re.findall(r'^\s*chain_id\s*:\s*\"([0-9a-fA-F-]{36})\"', vdisk_cfg, re.MULTILINE)))
emit_progress(3, "Parsing IDs for curator batching...")

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

t0 = time.time()
emit_progress(4, "Querying curator vdisk usage...")
curator_out = run_curator_vdisk_usage(raw_vdisk_ids, chunk_size=CURATOR_VDISK_CHUNK)
collector_timing["curator_vdisk_sec"] = round(time.time() - t0, 3)
t0 = time.time()
emit_progress(5, "Querying curator chain usage...")
curator_chain_out = run_curator_chain_usage(raw_chain_ids, chunk_size=CURATOR_CHAIN_CHUNK)
collector_timing["curator_chain_sec"] = round(time.time() - t0, 3)
collector_timing["container_count"] = len(container_names)
collector_timing["vdisk_count"] = len(raw_vdisk_ids)
collector_timing["chain_count"] = len(raw_chain_ids)
collector_timing["fast_mode"] = FAST_MODE
collector_timing["skip_nfs_ls"] = SKIP_NFS_LS
collector_timing["collector_workers"] = {"nfs": NFS_WORKERS, "curator": CURATOR_WORKERS}
collector_timing["collector_chunk"] = {"vdisk": CURATOR_VDISK_CHUNK, "chain": CURATOR_CHAIN_CHUNK, "retry": CURATOR_RETRY_CHUNK}

emit_progress(6, "Finalizing live scan output...")
print("===VDISK_CFG_START===")
print(vdisk_cfg)
print("===NCLI_SP_START===")
print(ncli_sp)
print("===NCLI_VM_START===")
print(ncli_vm)
print("===NCLI_VG_START===")
print(ncli_vg)
print("===NCLI_CTR_START===")
print(ncli_ctr)
print("===NFS_LS_START===")
print(nfs_ls_out)
print("===CURATOR_START===")
print(curator_out)
print("===CURATOR_CHAIN_USAGE_START===")
print(curator_chain_out)
print("===COLLECTOR_TIMING_START===")
print(json.dumps(collector_timing))
emit_progress(7, "DONE: live CVM scan complete.")
print("===COLLECTOR_OUTPUT_COMPLETE===")
sys.stdout.flush()
"""

        try:
            client.connect(
                hostname=self.host, port=self.port, username=self.username, password=self.password,
                timeout=30, banner_timeout=30, auth_timeout=30, look_for_keys=False, allow_agent=False
            )

            stdin, stdout, stderr = client.exec_command("python -", timeout=600)
            stdin.write(cvm_python_script)
            stdin.flush()
            stdin.channel.shutdown_write()

            stdout_chunks = []
            stderr_chunks = []
            progress_pattern = re.compile(r"^===PROGRESS:(\d+/\d+):(.*)===$")
            channel = stdout.channel
            idle_loops = 0
            while True:
                had_data = False
                if channel.recv_ready():
                    data = channel.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        had_data = True
                        stdout_chunks.append(data)
                        if progress_callback:
                            for line in data.splitlines():
                                match = progress_pattern.match(line.strip())
                                if match:
                                    progress_callback(match.group(1), match.group(2).strip())
                if channel.recv_stderr_ready():
                    err_data = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                    if err_data:
                        had_data = True
                        stderr_chunks.append(err_data)
                if had_data:
                    idle_loops = 0
                else:
                    idle_loops += 1
                    time.sleep(0.01)

                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready() and idle_loops >= 3:
                    break

            # Final drain pass to capture trailing buffered bytes.
            for _ in range(20):
                drained = False
                if channel.recv_ready():
                    data = channel.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        drained = True
                        stdout_chunks.append(data)
                        if progress_callback:
                            for line in data.splitlines():
                                match = progress_pattern.match(line.strip())
                                if match:
                                    progress_callback(match.group(1), match.group(2).strip())
                if channel.recv_stderr_ready():
                    err_data = channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                    if err_data:
                        drained = True
                        stderr_chunks.append(err_data)
                if not drained:
                    break
                time.sleep(0.005)

            raw_output = "".join(stdout_chunks)
            raw_stderr = "".join(stderr_chunks)
            if raw_stderr.strip():
                logger.warning("Live collector stderr had output: %s", raw_stderr.strip())
            raw_output = re.sub(r"^===PROGRESS:\d+/\d+:.*===\s*$", "", raw_output, flags=re.MULTILINE).strip()
            required_markers = [
                "===VDISK_CFG_START===",
                "===NCLI_SP_START===",
                "===NCLI_VM_START===",
                "===NCLI_VG_START===",
                "===NCLI_CTR_START===",
                "===NFS_LS_START===",
                "===CURATOR_START===",
                "===CURATOR_CHAIN_USAGE_START===",
                "===COLLECTOR_TIMING_START===",
                "===COLLECTOR_OUTPUT_COMPLETE===",
            ]
            missing_markers = [m for m in required_markers if m not in raw_output]
            if not missing_markers:
                raw_output = raw_output.replace("===COLLECTOR_OUTPUT_COMPLETE===", "").strip()
                return raw_output
            else:
                raise Exception("Failed to execute Nutanix collector script on CVM: incomplete live collector output (missing markers: %s)." % ", ".join(missing_markers))
        finally:
            client.close()
