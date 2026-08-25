#!/usr/bin/env python
# Save as collect_offline.py on CVM and run: python collect_offline.py
from __future__ import print_function
import subprocess, re, sys
from concurrent.futures import ThreadPoolExecutor

def run_cmd(cmd):
    try:
        env_setup = (
            "export PATH=/usr/local/nutanix/bin:/home/nutanix/cluster/bin:/home/nutanix/bin:$PATH; "
            "source /etc/profile >/dev/null 2>&1; "
            "source ~/.bashrc >/dev/null 2>&1; "
        )
        p = subprocess.Popen(
            env_setup + cmd,
            shell=True,
            executable='/bin/bash',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = p.communicate()
        return out.decode('utf-8', 'ignore') if out else ""
    except Exception as e:
        return "[ERROR] " + str(e)

print("🔍 [1/7] Extracting vdisk_config_printer metadata...")
vdisk_cfg = run_cmd("/usr/local/nutanix/bin/vdisk_config_printer")
if not vdisk_cfg.strip() or "command not found" in vdisk_cfg:
    vdisk_cfg = run_cmd("vdisk_config_printer")

print("📊 [2/7] Extracting NCLI metadata (VMs, VGs, Storage Pools, Containers)...")
ncli_vm = run_cmd("ncli vm ls")
ncli_vg = run_cmd("ncli volume-group ls")
ncli_sp = run_cmd("ncli storagepool ls")
ncli_ctr = run_cmd("ncli container ls")

print("🌳 [3/7] Extracting snapshot_tree_printer metadata...")
snapshot_tree = run_cmd("/usr/local/nutanix/bin/snapshot_tree_printer")
if not snapshot_tree.strip() or "command not found" in snapshot_tree:
    snapshot_tree = run_cmd("snapshot_tree_printer")

print("💿 [4/7] Parsing VDisk IDs & Chain IDs...")
raw_vdisk_ids = re.findall(r'^\s*vdisk_id\s*:\s*(\d+)', vdisk_cfg, re.MULTILINE)
vdisk_ids = sorted(list(set(raw_vdisk_ids)), key=lambda x: int(x))

raw_chain_ids = re.findall(r'chain_id\s*:\s*"([a-f0-9\-]{36})"', vdisk_cfg, re.MULTILINE)
chain_ids = sorted(list(set(raw_chain_ids)))
print("    Found %d unique VDisks and %d unique Chain IDs." % (len(vdisk_ids), len(chain_ids)))

def query_curator_vdisk_batch(batch_info):
    batch_num, ids_chunk = batch_info
    ids_str = ",".join(ids_chunk)
    cmd = "/usr/local/nutanix/bin/curator_cli get_vdisk_usage lookup_vdisk_ids=" + ids_str
    res = run_cmd(cmd)
    if "command not found" in res or "No such file" in res:
        cmd = "curator_cli get_vdisk_usage lookup_vdisk_ids=" + ids_str
        res = run_cmd(cmd)
    return (batch_num, res)

def query_curator_chain_batch(batch_info):
    batch_num, ids_chunk = batch_info
    ids_str = ",".join(ids_chunk)
    cmd = "/usr/local/nutanix/bin/curator_cli get_vdisk_chain_usage lookup_chain_ids=" + ids_str
    res = run_cmd(cmd)
    if "command not found" in res or "No such file" in res:
        cmd = "curator_cli get_vdisk_chain_usage lookup_chain_ids=" + ids_str
        res = run_cmd(cmd)
    return (batch_num, res)

print("🚀 [5/7] Querying Curator VDisk usage in parallel batches...")
chunk_size = 150
vdisk_batches = [(i // chunk_size + 1, vdisk_ids[i:i+chunk_size]) for i in range(0, len(vdisk_ids), chunk_size)]

with ThreadPoolExecutor(max_workers=8) as executor:
    vdisk_results = list(executor.map(query_curator_vdisk_batch, vdisk_batches))

vdisk_results.sort(key=lambda x: x[0])
curator_vdisk_out = "".join(["\n--- BATCH %d ---\n%s" % (b_num, res) for b_num, res in vdisk_results])

print("🚀 [6/7] Querying Curator VDisk Chain usage in parallel batches...")
chain_chunk_size = 100
chain_batches = [(i // chain_chunk_size + 1, chain_ids[i:i+chain_chunk_size]) for i in range(0, len(chain_ids), chain_chunk_size)]

with ThreadPoolExecutor(max_workers=8) as executor:
    chain_results = list(executor.map(query_curator_chain_batch, chain_batches))

chain_results.sort(key=lambda x: x[0])
curator_chain_out = "".join(["\n--- CHAIN BATCH %d ---\n%s" % (b_num, res) for b_num, res in chain_results])

out_filename = "vdisk_sniffer_offline.log"
print("💾 [7/7] Writing diagnostic bundle to %s..." % out_filename)
with open(out_filename, "w") as f:
    f.write("===VDISK_CFG_START===\n" + vdisk_cfg + "\n")
    f.write("===NCLI_VM_START===\n" + ncli_vm + "\n")
    f.write("===NCLI_VG_START===\n" + ncli_vg + "\n")
    f.write("===NCLI_SP_START===\n" + ncli_sp + "\n")
    f.write("===NCLI_CTR_START===\n" + ncli_ctr + "\n")
    f.write("===SNAPSHOT_TREE_START===\n" + snapshot_tree + "\n")
    f.write("===CURATOR_START===\n" + curator_vdisk_out + "\n")
    f.write("===CURATOR_CHAIN_USAGE_START===\n" + curator_chain_out + "\n")

print("\n✅ DONE! Download 'vdisk_sniffer_offline.log' and upload it to VDisk Sniffer.")
