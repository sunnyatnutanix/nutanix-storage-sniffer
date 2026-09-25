import logging
import os
import traceback
import json
import time
import threading
import uuid
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from app.cvm_collector import CVMCollector
from app.parser import (
    parse_vdisk_configure_printer,
    parse_snapshot_tree_printer,
    parse_curator_usage,
    parse_curator_chain_usage,
    parse_curator_garbage_report,
    parse_ncli_vms,
    parse_ncli_volume_groups,
    parse_ncli_storage_pool,
    parse_ncli_containers,
    parse_snapshot_tree_chain_ids,
    parse_ncli_containers_detailed,
)
from app.model_chain import VdiskNode, ChainNode, ChainTree, ContainerGraph

LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "vdisk_sniffer.log")
RAW_CVM_LOG_FILE = os.path.join(LOG_DIR, "raw_cvm_output.log")
RAW_CVM_LAST_SECTIONS_FILE = os.path.join(LOG_DIR, "raw_cvm_sections_last.json")
DEBUG_LOG_PATH = "/home/sre/vdisk-sniffer/.cursor/debug-2cdd75.log"
DEBUG_SESSION_ID = "2cdd75"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vdisk_sniffer")

app = FastAPI(title="VDisk Sniffer")
SCAN_JOB_TTL_SEC = 1800
SCAN_EVENT_POLL_SEC = 0.2
scan_jobs = {}
scan_jobs_lock = threading.Lock()

STATIC_DIR = "app/static"
if not os.path.exists(STATIC_DIR):
    STATIC_DIR = "static" 

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class ScanRequest(BaseModel):
    cvm_ip: str
    username: str = "nutanix"
    password: str


def _cleanup_expired_scan_jobs():
    cutoff = time.time() - SCAN_JOB_TTL_SEC
    with scan_jobs_lock:
        expired = [sid for sid, job in scan_jobs.items() if float(job.get("updated_at", 0.0)) < cutoff]
        for sid in expired:
            scan_jobs.pop(sid, None)


def _publish_scan_event(scan_id: str, event_type: str, payload: dict):
    now = time.time()
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)
        if not job:
            return
        seq = int(job.get("next_seq", 1))
        event_payload = {
            "seq": seq,
            "event": event_type,
            "timestamp": now,
            **payload
        }
        job["events"].append(event_payload)
        job["next_seq"] = seq + 1
        job["updated_at"] = now


def _run_scan_job(scan_id: str, req: ScanRequest):
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)
        if not job:
            return
        job["status"] = "running"
        job["updated_at"] = time.time()
    try:
        collector = CVMCollector(host=req.cvm_ip, username=req.username, password=req.password)

        def _on_progress(step_fraction: str, message: str):
            _publish_scan_event(scan_id, "step", {"step": step_fraction, "message": f"[{step_fraction}] {message}"})

        raw_output = collector.fetch_all_cvm_data(progress_callback=_on_progress)
        persist_raw_cvm_output(raw_output)
        result = process_raw_logs(raw_output, run_id="live-ssh")
        with scan_jobs_lock:
            job = scan_jobs.get(scan_id)
            if not job:
                return
            job["result"] = result
            job["status"] = "done"
            job["updated_at"] = time.time()
        _publish_scan_event(scan_id, "done", {"message": "Live scan completed."})
    except Exception as e:
        logger.error(f"SSH Scan job failed: {str(e)}")
        with scan_jobs_lock:
            job = scan_jobs.get(scan_id)
            if job:
                job["status"] = "error"
                job["error"] = str(e)
                job["updated_at"] = time.time()
        _publish_scan_event(scan_id, "error", {"message": str(e)})

def _debug_emit(run_id: str, hypothesis_id: str, location: str, message: str, data: dict):
    try:
        payload = {
            "sessionId": DEBUG_SESSION_ID,
            "id": f"log_{int(time.time() * 1000)}_{hypothesis_id}",
            "timestamp": int(time.time() * 1000),
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data
        }
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as fp:
            fp.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass

def persist_raw_cvm_output(raw_output: str):
    try:
        with open(RAW_CVM_LOG_FILE, "w", encoding="utf-8") as fp:
            fp.write(raw_output or "")
        sections = extract_log_sections(raw_output or "")
        section_meta = {k: len(v or "") for k, v in sections.items() if v}
        with open(RAW_CVM_LAST_SECTIONS_FILE, "w", encoding="utf-8") as fp:
            fp.write(json.dumps(section_meta, ensure_ascii=True, indent=2))
    except Exception as e:
        logger.warning(f"Failed to persist raw CVM output: {e}")

def format_bytes(bytes_val: int) -> str:
    if not bytes_val or bytes_val <= 0: return "0 KiB"
    val = float(bytes_val)
    if val < 1024**2: return f"{val / 1024:.2f} KiB"
    elif val < 1024**3: return f"{val / (1024**2):.2f} MiB"
    elif val < 1024**4: return f"{val / (1024**3):.2f} GiB"
    else: return f"{val / (1024**4):.2f} TiB"


def compute_chain_snap_share(chain_id: str, chain_vdisk_ids: list, chain_usage_map: dict, usage_map: dict) -> dict:
    """chain_snap_share = (logical_live - logical_shared_clone) * 2 - exclusive_sum."""
    stats = chain_usage_map.get(chain_id, {}) or {}
    logical_live = int(stats.get("logical_live", 0) or 0)
    logical_clone = int(stats.get("logical_shared_clone", 0) or 0)
    logical_exclusive = int(stats.get("logical_exclusive", 0) or 0)
    vids = list(chain_vdisk_ids or [])
    exclusive_sum = sum(int(usage_map.get(str(vd_id), 0) or 0) for vd_id in vids)
    terms = {
        "logical_live": logical_live,
        "logical_shared_clone": logical_clone,
        "logical_exclusive": logical_exclusive,
        "exclusive_sum": int(exclusive_sum),
        "snap_share": 0,
    }
    if logical_live == 0:
        source = "skipped_logical_live_zero"
        snap_share = 0
    elif logical_live == logical_exclusive:
        source = "skipped_live_equals_exclusive"
        snap_share = 0
    elif len(vids) <= 1:
        source = "skipped_single_vdisk"
        snap_share = 0
    else:
        snap_share = (logical_live - logical_clone) * 2 - exclusive_sum
        if snap_share <= 0:
            source = "skipped_non_positive"
            snap_share = 0
        else:
            source = "live_minus_clone_x2_minus_exclusive_sum"
            terms["snap_share"] = int(snap_share)
    return {
        "logical_live": logical_live,
        "logical_shared_clone": logical_clone,
        "logical_exclusive": logical_exclusive,
        "exclusive_sum": int(exclusive_sum),
        "snap_share": int(max(0, snap_share)),
        "terms": terms,
        "source": source,
    }


def build_chain_snap_share_leaf(chain_id: str, chain_vdisk_ids: list, computed: dict, container_name: str = None) -> dict:
    snap_share = int(computed.get("snap_share", 0) or 0)
    return {
        "name": str(chain_id),
        "chain_id": str(chain_id),
        "vdisk_id": None,
        "vdisk_ids": list(chain_vdisk_ids or []),
        "is_chain_snap_share_block": True,
        "value": snap_share,
        "real_bytes": snap_share,
        "formatted_size": format_bytes(snap_share),
        "snap_share_formula_source": computed.get("source"),
        "snap_share_formula_terms": computed.get("terms", {}),
        "container_name": container_name,
    }

def extract_log_sections(raw_output: str) -> dict:
    headers = [
        "===VDISK_CFG_START===", "===NCLI_VM_START===", "===NCLI_VG_START===",
        "===NCLI_SP_START===", "===NCLI_CTR_START===", "===SNAPSHOT_TREE_START===",
        "===SNAPSHOT_TREE_CHAIN_IDS_START===", "===CURATOR_START===", "===CURATOR_CHAIN_USAGE_START===",
        "===CURATOR_GARBAGE_START===", "===NFS_LS_START===", "===COLLECTOR_TIMING_START===",
    ]
    sections = {h: "" for h in headers}
    found_headers = []

    for h in headers:
        pos = raw_output.find(h)
        if pos != -1:
            found_headers.append((pos, h))

    if not found_headers:
        if "vdisk_id:" in raw_output:
            sections["===VDISK_CFG_START==="] = raw_output
        return sections

    found_headers.sort(key=lambda x: x[0])
    for i, (pos, header) in enumerate(found_headers):
        start_pos = pos + len(header)
        end_pos = found_headers[i + 1][0] if i + 1 < len(found_headers) else len(raw_output)
        sections[header] = raw_output[start_pos:end_pos].strip()

    return sections


def process_container_centric_logs(sections: dict):
    collector_timing = {}
    try:
        collector_timing = json.loads(sections.get("===COLLECTOR_TIMING_START===", "") or "{}")
    except Exception:
        collector_timing = {}
    debug_run_id = "snapshot_shared_classification"
    vdisks = parse_vdisk_configure_printer(sections.get("===VDISK_CFG_START===", ""))
    vdisk_by_id = {str(vd.get("vdisk_id")): vd for vd in vdisks if vd.get("vdisk_id") is not None}
    parent_by_child = {}
    parent_link_source_by_child = {}
    children_by_parent = {}
    for vd in vdisks:
        child_id = vd.get("vdisk_id")
        if child_id is None:
            continue
        child_s = str(child_id)
        resolved_parent = None
        resolved_source = None
        parent_id = vd.get("parent_vdisk_id")
        clone_source_id = vd.get("clone_source_vdisk_id")
        if parent_id is not None and str(parent_id).strip():
            resolved_parent = str(parent_id)
            resolved_source = "parent_vdisk_id"
        elif clone_source_id is not None and str(clone_source_id).strip():
            resolved_parent = str(clone_source_id)
            resolved_source = "clone_source_vdisk_id"
        if resolved_parent:
            parent_s = str(resolved_parent)
            parent_by_child[child_s] = parent_s
            parent_link_source_by_child[child_s] = resolved_source
            children_by_parent.setdefault(parent_s, []).append(child_s)
    # #region agent log
    _debug_emit(
        debug_run_id, "H1",
        "app/main.py:process_container_centric_logs:lineage_index",
        "Built lineage indexes for container-centric run",
        {
            "vdisk_count": len(vdisks),
            "parent_links_count": len(parent_by_child),
            "parent_link_source_counts": {
                "parent_vdisk_id": len([k for k, s in parent_link_source_by_child.items() if s == "parent_vdisk_id"]),
                "clone_source_vdisk_id": len([k for k, s in parent_link_source_by_child.items() if s == "clone_source_vdisk_id"]),
            },
            "roots_count_estimate": len([str(v.get('vdisk_id')) for v in vdisks if v.get('vdisk_id') is not None and str(v.get('vdisk_id')) not in parent_by_child])
        }
    )
    # #endregion
    containers = parse_ncli_containers_detailed(sections.get("===NCLI_CTR_START===", ""))
    vms = parse_ncli_vms(sections.get("===NCLI_VM_START===", ""))
    vgs = parse_ncli_volume_groups(sections.get("===NCLI_VG_START===", ""))
    nfs_raw_section = sections.get("===NFS_LS_START===", "")
    nfs_map = parse_nfs_ls_sections(nfs_raw_section)
    nfs_detailed_map = parse_nfs_ls_sections_detailed(nfs_raw_section)
    curator_usage_map = parse_curator_usage(sections.get("===CURATOR_START===", ""))
    chain_usage_map = parse_curator_chain_usage(sections.get("===CURATOR_CHAIN_USAGE_START===", ""))
    vdisk_by_nfs = parse_vdisk_map_by_nfs(vdisks)
    valid_nfs_names = {str(vd.get("nfs_file_name")).strip() for vd in vdisks if vd.get("nfs_file_name")}
    sp_info = parse_ncli_storage_pool(sections.get("===NCLI_SP_START===", ""))
    disk_uuid_to_vg = {}
    vg_uuid_to_name = {}
    for vg_uuid, vg in vgs.items():
        vg_uuid_to_name[vg_uuid] = vg["name"]
        for disk_uuid in vg.get("disk_uuids", []):
            disk_uuid_to_vg[disk_uuid] = vg["name"]

    vdisk_to_vm = {}
    for vm_key, vm_data in vms.items():
        vm_name = vm_data["name"]
        vm_uuid = vm_data.get("uuid")
        if vm_uuid:
            vdisk_to_vm[vm_uuid] = vm_name
        for vdisk_str in vm_data.get("vdisks", []):
            clean_vdisk = vdisk_str.split("::")[-1].strip()
            if clean_vdisk:
                vdisk_to_vm[clean_vdisk] = vm_name

    container_nodes = []
    total_physical = 0

    lineage_cache = {}
    chain_to_vdisk_ids = {}
    for vd in vdisks:
        cid = str(vd.get("chain_id") or "").strip()
        vid = str(vd.get("vdisk_id") or "").strip()
        if cid and vid:
            chain_to_vdisk_ids.setdefault(cid, [])
            if vid not in chain_to_vdisk_ids[cid]:
                chain_to_vdisk_ids[cid].append(vid)
    chain_has_parent_chain = {cid: False for cid in chain_to_vdisk_ids.keys()}
    for vd in vdisks:
        cid = str(vd.get("chain_id") or "").strip()
        if not cid:
            continue
        parent_chain_id = str(vd.get("parent_chain_id") or "").strip()
        if parent_chain_id and parent_chain_id != cid:
            chain_has_parent_chain[cid] = True
            continue
        child_vid = str(vd.get("vdisk_id") or "").strip()
        resolved_parent_id = parent_by_child.get(child_vid)
        if not resolved_parent_id:
            continue
        pvd = vdisk_by_id.get(str(resolved_parent_id), {})
        p_chain = str(pvd.get("chain_id") or "").strip()
        if p_chain and p_chain != cid:
            chain_has_parent_chain[cid] = True

    debug_target_chain_ids = {
        "11b3f48e-031b-4e71-88c9-9fcecf8c060b",
        "012ac263-463e-45c7-9427-e4f8e427efb1",
    }
    debug_target_root_vdisk_ids = {"76193", "76189"}

    # #region agent log
    _debug_emit(
        debug_run_id, "H1",
        "app/main.py:process_container_centric_logs:chain_parent_flag",
        "Target chain parent-chain eligibility",
        {
            "target_chain_parent_flags": {
                cid: bool(chain_has_parent_chain.get(cid, False))
                for cid in sorted(debug_target_chain_ids)
            }
        }
    )
    # #endregion

    chain_shared_cache = {}
    def compute_chain_shared_usage(chain_id: str):
        chain_id = str(chain_id or "").strip()
        if not chain_id:
            return {
                "shared_bytes": 0,
                "source": "missing_chain_id",
                "terms": {
                    "logical_live": 0,
                    "logical_shared_clone": 0,
                    "physical_peg": 0,
                    "exclusive_sum": 0
                }
            }
        if chain_id in chain_shared_cache:
            return chain_shared_cache[chain_id]
        stats = chain_usage_map.get(chain_id, {})
        logical_live = int(stats.get("logical_live", 0) or 0)
        logical_clone = int(stats.get("logical_shared_clone", 0) or 0)
        physical_peg = int(stats.get("physical_peg", 0) or 0)
        chain_vdisk_ids = chain_to_vdisk_ids.get(chain_id, [])
        exclusive_sum = sum(int(curator_usage_map.get(str(vd_id), 0) or 0) for vd_id in chain_vdisk_ids)
        if logical_clone > 0:
            shared_bytes = (logical_clone * 2)
            source = "curator_chain_x2"
        elif len(chain_vdisk_ids) <= 1:
            shared_bytes = 0
            source = "single_vdisk_zero_clone_no_shared"
        else:
            # Snapshot-chain leftover is owned by Chain Snap Share; do not count it here.
            shared_bytes = 0
            source = "zero_clone_use_chain_snap_share"
        payload = {
            "shared_bytes": int(shared_bytes),
            "source": source,
            "terms": {
                "logical_live": logical_live,
                "logical_shared_clone": logical_clone,
                "physical_peg": physical_peg,
                "exclusive_sum": int(exclusive_sum)
            }
        }
        chain_shared_cache[chain_id] = payload
        return payload

    def lineage_role(vdisk_id: str):
        has_parent = vdisk_id in parent_by_child
        has_children = len(children_by_parent.get(vdisk_id, [])) > 0
        if has_children and has_parent:
            return "intermediate"
        if has_children:
            return "root"
        return "leaf"

    def lineage_ancestors(vdisk_id: str):
        ancestors = []
        seen = set()
        cur = vdisk_id
        while cur and cur in parent_by_child and cur not in seen:
            seen.add(cur)
            cur = parent_by_child.get(cur)
            if cur:
                ancestors.append(cur)
        return ancestors

    def lineage_root(vdisk_id: str):
        root = vdisk_id
        seen = set()
        while root in parent_by_child and root not in seen:
            seen.add(root)
            root = parent_by_child[root]
        return root

    def is_same_chain_snapshot_continuation(child_vd: dict, parent_vd: dict):
        if not child_vd or not parent_vd:
            return False
        child_chain_id = str(child_vd.get("chain_id") or "").strip()
        parent_chain_id = str(parent_vd.get("chain_id") or "").strip()
        if not child_chain_id or not parent_chain_id:
            return False
        same_chain = child_chain_id == parent_chain_id
        mutability_text = (
            str(child_vd.get("mutability_state") or "") + " " +
            str(parent_vd.get("mutability_state") or "")
        )
        has_snapshot_marker = "kImmutableSnapshot" in mutability_text
        return same_chain and has_snapshot_marker

    def calc_subtree_shared(vdisk_id: str, seen=None):
        if seen is None:
            seen = set()
        if vdisk_id in seen:
            return 0
        seen.add(vdisk_id)
        children = children_by_parent.get(vdisk_id, [])
        node_shared = 0
        for cid in children:
            c_vd = vdisk_by_id.get(str(cid), {})
            c_chain_shared = compute_chain_shared_usage(str(c_vd.get("chain_id") or ""))
            c_shared = int(c_chain_shared.get("shared_bytes", 0))
            node_shared = max(node_shared, c_shared)
        child_subtree_max = 0
        for cid in children:
            child_subtree_max = max(child_subtree_max, calc_subtree_shared(cid, seen.copy()))
        return max(node_shared, child_subtree_max)

    def build_lineage_summary(vdisk_id: str):
        vdisk_id = str(vdisk_id)
        if vdisk_id in lineage_cache:
            return lineage_cache[vdisk_id]
        parent_id = parent_by_child.get(vdisk_id)
        children_ids = sorted(children_by_parent.get(vdisk_id, []), key=lambda x: int(x) if x.isdigit() else x)
        child_rows = []
        node_shared = 0
        for cid in children_ids:
            c_vd = vdisk_by_id.get(str(cid), {})
            c_chain_shared = compute_chain_shared_usage(str(c_vd.get("chain_id") or ""))
            inherited = int(c_chain_shared.get("shared_bytes", 0))
            curator_exclusive = int(curator_usage_map.get(str(cid), 0))
            node_shared = max(node_shared, inherited)
            child_rows.append({
                "vdisk_id": str(cid),
                "inherited_usage_bytes": inherited,
                "curator_exclusive_usage_bytes": curator_exclusive,
                "formatted_inherited_usage": format_bytes(inherited),
                "formatted_curator_exclusive_usage": format_bytes(curator_exclusive),
                "shared_formula_source": c_chain_shared.get("source"),
                "shared_formula_terms": c_chain_shared.get("terms", {}),
            })
        ancestors = lineage_ancestors(vdisk_id)
        summary = {
            "current_vdisk_id": vdisk_id,
            "parent_vdisk_id": parent_id,
            "children_vdisk_ids": children_ids,
            "lineage_role": lineage_role(vdisk_id),
            "lineage_root_vdisk_id": lineage_root(vdisk_id),
            "ancestors_vdisk_ids": ancestors,
            "depth_from_root": len(ancestors),
            "node_shared_storage_bytes": node_shared,
            "formatted_node_shared_storage": format_bytes(node_shared),
            "subtree_shared_storage_bytes": calc_subtree_shared(vdisk_id),
            "formatted_subtree_shared_storage": format_bytes(calc_subtree_shared(vdisk_id)),
            "child_details": child_rows,
            "orphan_parent_record": bool(parent_id and str(parent_id) not in vdisk_by_id)
        }
        lineage_cache[vdisk_id] = summary
        return summary

    def normalize_curator_primary_sources(container_children: list):
        for group in container_children:
            gname = str(group.get("name", ""))
            for child in group.get("children", []):
                if not isinstance(child, dict):
                    continue
                if gname == "Shared Storage" or child.get("is_shared_parent_vdisk"):
                    if not child.get("display_source"):
                        child["display_source"] = "curator_chain_x2"
                elif str(child.get("name", "")).startswith("VDisk-"):
                    child["display_source"] = "curator_cli"

    for c in containers:
        c_name = c.get("name", "UnknownContainer")
        try:
            replication_factor = int(str(c.get("replication_factor") or "2").strip())
            if replication_factor <= 0:
                replication_factor = 2
        except Exception:
            replication_factor = 2
        nfs_names = [n for n in nfs_map.get(c_name, []) if n in valid_nfs_names]
        entity_groups = {}
        shared_root_nodes = {}
        dummy_root_candidates_by_chain = {}
        chain_ids_with_real_root = set()
        c_total = 0

        debug_classification_rows = []
        candidate_vdisks = []
        for nfs_name in nfs_names:
            vd = vdisk_by_nfs.get(nfs_name)
            if vd:
                candidate_vdisks.append(vd)
        container_id_short = str(c.get("id_short", "")).strip()
        for vd in vdisks:
            if str(vd.get("container_id", "")).strip() == container_id_short:
                candidate_vdisks.append(vd)
        unique_candidates = {}
        for vd in candidate_vdisks:
            cid = str(vd.get("vdisk_id", "")).strip()
            if cid and cid not in unique_candidates:
                unique_candidates[cid] = vd
        container_vdisk_ids = sorted(unique_candidates.keys(), key=lambda x: int(x) if x.isdigit() else x)
        # Per-container NFS detail index to preserve path semantics like /vgdisk/<uuid>.
        container_nfs_detail = {}
        for item in nfs_detailed_map.get(c_name, []):
            nm = str(item.get("name", "")).strip()
            if nm and nm not in container_nfs_detail:
                container_nfs_detail[nm] = item

        for vd in unique_candidates.values():
            vdisk_id = str(vd.get("vdisk_id", ""))
            nfs_name = str(vd.get("nfs_file_name", "")).strip()
            curator_exclusive = int(curator_usage_map.get(vdisk_id, 0))
            params_reserved = int(((vd.get("params") or {}).get("total_reserved_capacity", 0)) or 0)
            has_hint_total_reserved_capacity = "hint_total_reserved_capacity" in vd
            # ESXi thick-provision detection:
            # use only total_reserved_capacity and explicitly exclude vdisks that
            # expose hint_total_reserved_capacity (these are not classified as thick here).
            thick_reserved_raw_bytes = params_reserved if (params_reserved > 0 and not has_hint_total_reserved_capacity) else 0
            is_thick_prov_vdisk = thick_reserved_raw_bytes > 0
            # Thick-provisioned vdisks render with reserved capacity scaled by
            # container replication factor instead of curator exclusive usage.
            thick_prov_vdisk_bytes = thick_reserved_raw_bytes * replication_factor if is_thick_prov_vdisk else 0
            primary_usage_bytes = thick_prov_vdisk_bytes if is_thick_prov_vdisk else curator_exclusive
            primary_source = "thick_prov_total_reserved_capacity_x_rf" if is_thick_prov_vdisk else "curator_cli"
            c_total += primary_usage_bytes

            node = vd.copy()
            chain_stats = chain_usage_map.get(str(vd.get("chain_id") or ""), {})
            chain_shared = compute_chain_shared_usage(str(vd.get("chain_id") or ""))
            curator_shared_estimate = int(chain_shared.get("shared_bytes", 0))
            node.update({
                "name": f"VDisk-{vdisk_id}",
                "nfs_file_name": nfs_name,
                "value": primary_usage_bytes if primary_usage_bytes > 0 else 1,
                "real_bytes": primary_usage_bytes,
                "display_source": primary_source,
                "physical_curator_bytes": curator_exclusive,
                "formatted_curator_physical": format_bytes(curator_exclusive),
                "formatted_size": format_bytes(primary_usage_bytes),
                "is_thick_prov_vdisk": is_thick_prov_vdisk,
                "thick_prov_raw_bytes": thick_reserved_raw_bytes,
                "thick_prov_vdisk_bytes": thick_prov_vdisk_bytes,
                "replication_factor": replication_factor,
                "formatted_thick_prov_vdisk_size": format_bytes(thick_prov_vdisk_bytes),
                "inherited_usage_bytes": curator_shared_estimate,
                "formatted_inherited_usage": format_bytes(curator_shared_estimate),
                "curator_shared_estimated_bytes": curator_shared_estimate,
                "formatted_curator_shared_estimated": format_bytes(curator_shared_estimate),
                "chain_stats": chain_stats,
                "shared_formula_source": chain_shared.get("source"),
                "shared_formula_terms": chain_shared.get("terms", {}),
                "classification_reason": "snapshot" if "Immutable" in str(vd.get("mutability_state", "")) else "standard",
                "container_name": c_name,
                "lineage_summary": build_lineage_summary(vdisk_id),
            })
            owner_vm_id = vd.get("owner_id")
            mapped_vm = None
            if owner_vm_id and owner_vm_id in vdisk_to_vm:
                mapped_vm = vdisk_to_vm[owner_vm_id]
            elif owner_vm_id and owner_vm_id in vms:
                mapped_vm = vms[owner_vm_id]["name"]
            elif vd.get("vdisk_name") and vd.get("vdisk_name") in vdisk_to_vm:
                mapped_vm = vdisk_to_vm[vd.get("vdisk_name")]
            elif vdisk_id and str(vdisk_id) in vdisk_to_vm:
                mapped_vm = vdisk_to_vm[str(vdisk_id)]
            else:
                for _, vm_data in vms.items():
                    for v_str in vm_data.get("vdisks", []):
                        if (vd.get("vdisk_name") and vd.get("vdisk_name") in v_str) or (vdisk_id and str(vdisk_id) in v_str):
                            mapped_vm = vm_data["name"]
                            break
                    if mapped_vm:
                        break

            mapped_vg = None
            vg_resolution_method = None
            nfs_file_name = vd.get("nfs_file_name", "")
            vdisk_uuid = str(vd.get("vdisk_uuid") or "").strip()
            if vdisk_uuid and vdisk_uuid in disk_uuid_to_vg:
                mapped_vg = disk_uuid_to_vg[vdisk_uuid]
                vg_resolution_method = "vdisk_uuid"
            elif nfs_file_name in disk_uuid_to_vg:
                mapped_vg = disk_uuid_to_vg[nfs_file_name]
                vg_resolution_method = "nfs_file_name_uuid"
            elif nfs_file_name:
                nfs_item = container_nfs_detail.get(nfs_file_name)
                if nfs_item and nfs_item.get("is_vgdisk_path") and nfs_file_name in disk_uuid_to_vg:
                    mapped_vg = disk_uuid_to_vg[nfs_file_name]
                    vg_resolution_method = "nfs_vgdisk_path"

            is_to_remove = bool(vd.get("to_remove", False))
            is_in_recycle_bin = bool(vd.get("in_recycle_bin", False))
            is_snapshot = "Immutable" in str(vd.get("mutability_state", ""))
            node["is_to_remove"] = is_to_remove
            node["is_in_recycle_bin"] = is_in_recycle_bin
            if is_in_recycle_bin:
                mapped_entity = "Recycle Bin"
            elif is_to_remove:
                mapped_entity = "Pending Deletion (to_remove)"
            elif is_snapshot:
                mapped_entity = "Snapshots"
            elif mapped_vm:
                mapped_entity = f"VM: {mapped_vm}"
            elif mapped_vg:
                mapped_entity = f"VG: {mapped_vg}"
            else:
                mapped_entity = "VDisks"
            if mapped_entity.startswith("VM:"):
                node["classification_reason"] = "vm"
            elif mapped_entity.startswith("VG:"):
                node["classification_reason"] = "vg"
            elif mapped_entity == "Snapshots":
                node["classification_reason"] = "snapshot"
            elif mapped_entity == "Recycle Bin":
                node["classification_reason"] = "recycle_bin"
            elif mapped_entity == "Pending Deletion (to_remove)":
                node["classification_reason"] = "pending_deletion"
            else:
                node["classification_reason"] = node.get("classification_reason", "vdisk")
            node["mapped_vm_name"] = mapped_vm
            node["mapped_vg_name"] = mapped_vg
            node["mapped_entity_name"] = mapped_entity
            node["vg_resolution_method"] = vg_resolution_method
            node["vg_uuid_match"] = vdisk_uuid if (mapped_vg and vg_resolution_method == "vdisk_uuid") else None
            entity_groups.setdefault(mapped_entity, []).append(node)

            raw_parent_vdisk_id = vd.get("parent_vdisk_id")
            child_vdisk_id = str(vd.get("vdisk_id") or "").strip()
            resolved_parent_vdisk_id = parent_by_child.get(child_vdisk_id)
            parent_link_source = parent_link_source_by_child.get(child_vdisk_id)
            chain_id = str(vd.get("chain_id") or "").strip()
            parent_chain_id = None
            if resolved_parent_vdisk_id:
                parent_node = vdisk_by_id.get(str(resolved_parent_vdisk_id), {})
                parent_chain_id = parent_node.get("chain_id")
            has_shared_signal = curator_shared_estimate > 0
            is_snapshot_same_chain = False
            include_same_chain_clone_shared = False
            include_same_chain_vg_shared = False
            added_to_shared_root = False
            if resolved_parent_vdisk_id:
                immediate_parent_id = str(resolved_parent_vdisk_id)
                parent_vd = vdisk_by_id.get(immediate_parent_id, {})
                root_parent_id = lineage_root(immediate_parent_id)
                is_snapshot_same_chain = is_same_chain_snapshot_continuation(vd, parent_vd)
                include_same_chain_clone_shared = bool(
                    is_snapshot_same_chain and chain_shared.get("source") == "curator_chain_x2"
                )
                include_same_chain_vg_shared = bool(
                    is_snapshot_same_chain and str(mapped_entity).startswith("VG:") and has_shared_signal
                )
                if has_shared_signal and (
                    not is_snapshot_same_chain
                    or include_same_chain_clone_shared
                    or include_same_chain_vg_shared
                ):
                    if chain_id in debug_target_chain_ids or root_parent_id in debug_target_root_vdisk_ids:
                        # #region agent log
                        _debug_emit(
                            debug_run_id, "H2",
                            "app/main.py:process_container_centric_logs:real_root_candidate",
                            "Real-root candidate evaluated for target lineage",
                            {
                                "container_name": c_name,
                                "vdisk_id": vdisk_id,
                                "chain_id": chain_id,
                                "resolved_parent_vdisk_id": resolved_parent_vdisk_id,
                                "root_parent_id": root_parent_id,
                                "has_shared_signal": has_shared_signal,
                                "is_snapshot_same_chain": is_snapshot_same_chain,
                                "include_same_chain_clone_shared": include_same_chain_clone_shared,
                                "include_same_chain_vg_shared": include_same_chain_vg_shared,
                                "shared_source": chain_shared.get("source"),
                                "shared_bytes": curator_shared_estimate,
                            }
                        )
                        # #endregion
                    child_shared_primary = curator_shared_estimate
                    if root_parent_id not in shared_root_nodes:
                        shared_root_nodes[root_parent_id] = {
                            "max_curator_shared_estimated_bytes": curator_shared_estimate,
                            "max_primary_shared_bytes": child_shared_primary,
                            "is_dummy_lineage_root": False,
                            "root_chain_id": chain_id,
                            "anchor_vdisk_id": immediate_parent_id,
                            "shared_formula_source": chain_shared.get("source"),
                            "shared_formula_terms": chain_shared.get("terms", {}),
                            "child_vdisk_ids": [vdisk_id],
                            "immediate_parent_ids": [immediate_parent_id]
                        }
                    else:
                        if child_shared_primary >= int(shared_root_nodes[root_parent_id].get("max_primary_shared_bytes", 0)):
                            shared_root_nodes[root_parent_id]["shared_formula_source"] = chain_shared.get("source")
                            shared_root_nodes[root_parent_id]["shared_formula_terms"] = chain_shared.get("terms", {})
                        shared_root_nodes[root_parent_id]["max_curator_shared_estimated_bytes"] = max(
                            shared_root_nodes[root_parent_id]["max_curator_shared_estimated_bytes"], curator_shared_estimate
                        )
                        shared_root_nodes[root_parent_id]["max_primary_shared_bytes"] = max(
                            shared_root_nodes[root_parent_id]["max_primary_shared_bytes"], child_shared_primary
                        )
                        shared_root_nodes[root_parent_id]["anchor_vdisk_id"] = shared_root_nodes[root_parent_id].get("anchor_vdisk_id") or immediate_parent_id
                        shared_root_nodes[root_parent_id]["child_vdisk_ids"].append(vdisk_id)
                        shared_root_nodes[root_parent_id]["immediate_parent_ids"].append(immediate_parent_id)
                    if chain_id:
                        chain_ids_with_real_root.add(chain_id)
                    node["classification_reason"] = "shared_clone_lineage"
                    added_to_shared_root = True
                elif is_snapshot_same_chain:
                    node["classification_reason"] = "snapshot_same_chain_excluded_from_shared"
                if include_same_chain_clone_shared:
                    node["classification_reason"] = "snapshot_same_chain_included_for_clone_shared"
                if include_same_chain_vg_shared:
                    node["classification_reason"] = "snapshot_same_chain_included_for_vg_shared"
            elif (
                has_shared_signal
                and chain_id
                and not chain_has_parent_chain.get(chain_id, False)
                and chain_shared.get("source") == "snapshot_chain_live2_peg_minus_exclusive_sum"
            ):
                synthetic_root_id = f"dummy-root-chain-{chain_id}"
                if chain_id in debug_target_chain_ids:
                    # #region agent log
                    _debug_emit(
                        debug_run_id, "H3",
                        "app/main.py:process_container_centric_logs:dummy_root_candidate",
                        "Dummy-root candidate evaluated for target lineage",
                        {
                            "container_name": c_name,
                            "vdisk_id": vdisk_id,
                            "chain_id": chain_id,
                            "synthetic_root_id": synthetic_root_id,
                            "has_shared_signal": has_shared_signal,
                            "chain_has_parent_chain": bool(chain_has_parent_chain.get(chain_id, False)),
                            "shared_source": chain_shared.get("source"),
                            "shared_bytes": curator_shared_estimate,
                        }
                    )
                    # #endregion
                child_shared_primary = curator_shared_estimate
                chain_dummy = dummy_root_candidates_by_chain.get(chain_id)
                if not chain_dummy:
                    chain_dummy = {
                        "synthetic_root_id": synthetic_root_id,
                        "max_curator_shared_estimated_bytes": curator_shared_estimate,
                        "max_primary_shared_bytes": child_shared_primary,
                        "is_dummy_lineage_root": True,
                        "root_chain_id": chain_id,
                        "anchor_vdisk_id": vdisk_id,
                        "shared_formula_source": chain_shared.get("source"),
                        "shared_formula_terms": chain_shared.get("terms", {}),
                        "child_vdisk_ids": [vdisk_id],
                        "immediate_parent_ids": []
                    }
                    dummy_root_candidates_by_chain[chain_id] = chain_dummy
                else:
                    if child_shared_primary >= int(chain_dummy.get("max_primary_shared_bytes", 0)):
                        chain_dummy["shared_formula_source"] = chain_shared.get("source")
                        chain_dummy["shared_formula_terms"] = chain_shared.get("terms", {})
                        chain_dummy["anchor_vdisk_id"] = vdisk_id
                    chain_dummy["max_curator_shared_estimated_bytes"] = max(
                        chain_dummy["max_curator_shared_estimated_bytes"], curator_shared_estimate
                    )
                    chain_dummy["max_primary_shared_bytes"] = max(
                        chain_dummy["max_primary_shared_bytes"], child_shared_primary
                    )
                    chain_dummy["child_vdisk_ids"].append(vdisk_id)
                node["classification_reason"] = "shared_clone_lineage_dummy_root"
                added_to_shared_root = True

            debug_classification_rows.append({
                "vdisk_id": vdisk_id,
                "raw_parent_vdisk_id": str(raw_parent_vdisk_id) if raw_parent_vdisk_id is not None else None,
                "resolved_parent_vdisk_id": resolved_parent_vdisk_id,
                "parent_link_source": parent_link_source,
                "vdisk_chain_id": vd.get("chain_id"),
                "parent_chain_id": parent_chain_id,
                "mutability_state": vd.get("mutability_state"),
                "curator_shared_estimate": curator_shared_estimate,
                "shared_formula_source": chain_shared.get("source"),
                "shared_formula_terms": chain_shared.get("terms", {}),
                "added_to_shared_root": bool(added_to_shared_root),
                "same_chain_snapshot_excluded": bool(is_snapshot_same_chain),
                "classification_reason": node.get("classification_reason"),
                "resolved_root_parent_id": lineage_root(str(resolved_parent_vdisk_id)) if resolved_parent_vdisk_id else None
            })
        for candidate_chain_id, candidate_info in dummy_root_candidates_by_chain.items():
            if candidate_chain_id in chain_ids_with_real_root:
                continue
            candidate_root_id = str(candidate_info.get("synthetic_root_id"))
            shared_root_nodes[candidate_root_id] = candidate_info
        for group_nodes in entity_groups.values():
            group_nodes.sort(key=lambda x: x.get("real_bytes", 0), reverse=True)

        shared_storage_nodes = []
        for pvid, info in shared_root_nodes.items():
            max_curator_shared_est = int(info.get("max_curator_shared_estimated_bytes", 0))
            primary_shared = int(info.get("max_primary_shared_bytes", 0))
            is_dummy_root = bool(info.get("is_dummy_lineage_root"))
            parent_vd = {} if is_dummy_root else vdisk_by_id.get(pvid, {})
            parent_container_id = parent_vd.get("container_id", c.get("id_short"))
            parent_nfs_name = parent_vd.get("nfs_file_name", "")
            root_chain_id = str(info.get("root_chain_id") or "")
            anchor_vdisk_id = str(info.get("anchor_vdisk_id") or "")
            node_name = f"Lineage Root VDisk-Chain-{root_chain_id}" if is_dummy_root else f"Lineage Root VDisk-{pvid}"
            node_vdisk_id = anchor_vdisk_id if is_dummy_root else pvid
            shared_storage_nodes.append({
                **parent_vd,
                "name": node_name,
                "vdisk_id": node_vdisk_id,
                "parent_vdisk_id": (anchor_vdisk_id if is_dummy_root else pvid),
                "is_shared_parent_vdisk": True,
                "is_dummy_lineage_root": is_dummy_root,
                "is_lineage_root_accounted": True,
                "lineage_role": ("root" if is_dummy_root else lineage_role(pvid)),
                "value": primary_shared if primary_shared > 0 else 1,
                "real_bytes": primary_shared,
                "display_source": str(info.get("shared_formula_source") or "curator_chain_x2"),
                "shared_storage_bytes": primary_shared,
                "shared_storage_curator_estimated_bytes": max_curator_shared_est,
                "shared_formula_source": info.get("shared_formula_source"),
                "shared_formula_terms": info.get("shared_formula_terms", {}),
                "formatted_size": format_bytes(primary_shared),
                "formatted_shared_storage": format_bytes(primary_shared),
                "formatted_inherited_usage": format_bytes(max_curator_shared_est),
                "inherited_usage_bytes": max_curator_shared_est,
                "formatted_shared_storage_curator_estimated": format_bytes(max_curator_shared_est),
                "container_id": parent_container_id,
                "nfs_file_name": parent_nfs_name,
                "child_vdisk_ids": sorted(set(info.get("child_vdisk_ids", []))),
                "immediate_parent_ids": sorted(set(info.get("immediate_parent_ids", []))),
                "container_name": c_name,
                "lineage_summary": (None if is_dummy_root else build_lineage_summary(pvid)),
                "classification_reason": ("shared_storage_root_dummy" if is_dummy_root else "shared_storage_root"),
                "is_to_remove": bool(parent_vd.get("to_remove", False)),
                "root_chain_id": root_chain_id,
            })
            if str(node_vdisk_id) in debug_target_root_vdisk_ids or str(root_chain_id) in debug_target_chain_ids:
                # #region agent log
                _debug_emit(
                    debug_run_id, "H4",
                    "app/main.py:process_container_centric_logs:shared_node_emit",
                    "Shared node emitted for target root or chain",
                    {
                        "container_name": c_name,
                        "node_name": node_name,
                        "node_vdisk_id": node_vdisk_id,
                        "is_dummy_lineage_root": is_dummy_root,
                        "root_chain_id": root_chain_id,
                        "shared_storage_bytes": primary_shared,
                        "child_vdisk_ids": sorted(set(info.get("child_vdisk_ids", []))),
                        "immediate_parent_ids": sorted(set(info.get("immediate_parent_ids", []))),
                    }
                )
                # #endregion
        # #region agent log
        _debug_emit(
            debug_run_id, "H2",
            "app/main.py:process_container_centric_logs:shared_classification",
            "Snapshot/shared classification inputs for parent-child vdisks",
            {
                "container_name": c_name,
                "rows": debug_classification_rows[:300]
            }
        )
        # #endregion

        # #region agent log
        _debug_emit(
            debug_run_id, "H3",
            "app/main.py:process_container_centric_logs:shared_roots",
            "Shared roots generated for container",
            {
                "container_name": c_name,
                "shared_root_ids": sorted(list(shared_root_nodes.keys())),
                "shared_root_nodes_count": len(shared_root_nodes)
            }
        )
        # #endregion
        target_chain_root_entries = []
        for _pvid, _info in shared_root_nodes.items():
            if str(_info.get("root_chain_id") or "") in debug_target_chain_ids:
                target_chain_root_entries.append({
                    "root_id": str(_pvid),
                    "is_dummy_lineage_root": bool(_info.get("is_dummy_lineage_root", False)),
                    "root_chain_id": str(_info.get("root_chain_id") or ""),
                    "max_primary_shared_bytes": int(_info.get("max_primary_shared_bytes", 0) or 0),
                    "child_vdisk_ids": sorted(set(_info.get("child_vdisk_ids", []))),
                })
        if target_chain_root_entries:
            # #region agent log
            _debug_emit(
                debug_run_id, "H5",
                "app/main.py:process_container_centric_logs:target_chain_root_summary",
                "Target chain root entries summary before final shared nodes",
                {
                    "container_name": c_name,
                    "target_chain_root_entries": target_chain_root_entries,
                }
            )
            # #endregion
        shared_storage_nodes.sort(key=lambda x: x.get("real_bytes", 0), reverse=True)
        shared_storage_total = sum(n.get("real_bytes", 0) for n in shared_storage_nodes)

        container_children = []
        for group_name, group_nodes in entity_groups.items():
            group_total = sum(int(v.get("real_bytes", 0) or 0) for v in group_nodes)
            container_children.append({
                "name": group_name,
                "aggregate_exclusive_bytes": group_total,
                "formatted_size": format_bytes(group_total),
                "children": group_nodes
            })
        explicit_res_bytes = int(c.get("explicit_res_logical_bytes", 0) or 0)
        explicit_res_scaled_bytes = explicit_res_bytes * replication_factor
        if shared_storage_nodes:
            container_children.append({
                "name": "Shared Storage",
                "aggregate_exclusive_bytes": shared_storage_total,
                "formatted_size": format_bytes(shared_storage_total),
                "children": shared_storage_nodes
            })

        # Container reservation residual:
        # Explicit Reserved(Logical)*ReplicationFactor minus all other consumers in the container.
        # Thick provisioned vdisks are already included in c_total at vdisk level.
        other_container_total = c_total + shared_storage_total
        explicit_residual_bytes = explicit_res_scaled_bytes - other_container_total
        if explicit_residual_bytes > 0:
            container_children.append({
                "name": "Reserved Available Space",
                "aggregate_exclusive_bytes": explicit_residual_bytes,
                "formatted_size": format_bytes(explicit_residual_bytes),
                "children": [{
                    "name": "Reserved Available Space",
                    "is_explicit_reserve_block": True,
                    "container_name": c_name,
                    "value": explicit_residual_bytes,
                    "real_bytes": explicit_residual_bytes,
                    "raw_explicit_reserve_bytes": explicit_res_bytes,
                    "scaled_explicit_reserve_bytes": explicit_res_scaled_bytes,
                    "other_container_total_bytes": other_container_total,
                    "formula": "reserved_available_space_equals_explicit_res_logical_x_rf_minus_all_container_usage",
                    "scaled_by_replication_factor": True,
                    "display_source": "ncli_container_logical_residual",
                    "formatted_size": format_bytes(explicit_residual_bytes),
                }]
            })

        c_total_with_shared = other_container_total + max(0, explicit_residual_bytes)
        normalize_curator_primary_sources(container_children)
        container_children.sort(
            key=lambda g: (
                -int(g.get("aggregate_exclusive_bytes", 0) or 0),
                str(g.get("name", ""))
            )
        )

        container_node = {
            "name": c_name,
            "container_id": c.get("id_short"),
            "container_vdisk_count": len(container_vdisk_ids),
            "aggregate_exclusive_bytes": c_total_with_shared,
            "formatted_size": format_bytes(c_total_with_shared),
            "container_used_space_physical": c.get("used_space_physical"),
            "container_used_space_physical_bytes": c.get("used_space_physical_bytes", 0),
            "container_free_space_physical": c.get("free_space_physical"),
            "container_max_capacity_physical": c.get("max_capacity_physical"),
            "explicit_res_logical": c.get("explicit_res_logical"),
            "explicit_res_logical_bytes": c.get("explicit_res_logical_bytes", 0),
            "explicit_res_logical_scaled_bytes": explicit_res_scaled_bytes,
            "explicit_res_logical_residual_bytes": max(0, explicit_residual_bytes),
            "thick_prov_logical": c.get("thick_prov_logical"),
            "thick_prov_logical_bytes": c.get("thick_prov_logical_bytes", 0),
            "replication_factor": replication_factor,
            "children": container_children
        }
        container_nodes.append(container_node)
        total_physical += c_total_with_shared

    container_nodes.sort(key=lambda x: x.get("aggregate_exclusive_bytes", 0), reverse=True)
    sp_capacity = sp_info.get("capacity_bytes", 0) or sp_info.get("used_bytes", 0)
    sp_used = sp_info.get("used_bytes", total_physical)
    sp_free = sp_info.get("free_bytes", max(sp_capacity - sp_used, 0))

    return {
        "status": "success",
        "collector_timing": collector_timing,
        "tree": {
            "name": f"Storage Pool: {sp_info.get('name', 'Nutanix_SP')}",
            "formatted_size": format_bytes(sp_capacity),
            "children": [
                {
                    "name": f"Used Space ({format_bytes(sp_used)})",
                    "formatted_size": format_bytes(sp_used),
                    "children": container_nodes
                },
                {
                    "name": f"Free Space ({format_bytes(sp_free)})",
                    "value": sp_free,
                    "is_free": True,
                    "formatted_size": format_bytes(sp_free)
                }
            ]
        }
    }

def _extract_parent_links(vdisks: list):
    parent_by_child = {}
    children_by_parent = {}
    for vd in vdisks:
        child_id = vd.get("vdisk_id")
        if child_id is None:
            continue
        child_s = str(child_id)
        parent_id = vd.get("parent_vdisk_id")
        clone_source_id = vd.get("clone_source_vdisk_id")
        resolved_parent = None
        if parent_id is not None and str(parent_id).strip() and str(parent_id) != "0":
            resolved_parent = str(parent_id)
        elif clone_source_id is not None and str(clone_source_id).strip() and str(clone_source_id) != "0":
            resolved_parent = str(clone_source_id)
        if resolved_parent:
            parent_by_child[child_s] = resolved_parent
            children_by_parent.setdefault(resolved_parent, []).append(child_s)
    return parent_by_child, children_by_parent


def process_container_chain_graph_logs(sections: dict):
    collector_timing = {}
    try:
        collector_timing = json.loads(sections.get("===COLLECTOR_TIMING_START===", "") or "{}")
    except Exception:
        collector_timing = {}

    vdisks = parse_vdisk_configure_printer(sections.get("===VDISK_CFG_START===", ""))
    vdisk_by_id = {str(vd.get("vdisk_id")): vd for vd in vdisks if vd.get("vdisk_id") is not None}
    parent_by_child, children_by_parent = _extract_parent_links(vdisks)

    def lineage_root(vdisk_id: str):
        cur = str(vdisk_id or "")
        seen = set()
        while cur and cur in parent_by_child and cur not in seen:
            seen.add(cur)
            cur = str(parent_by_child.get(cur) or "")
        return cur or None

    def lineage_role(vdisk_id: str):
        vid = str(vdisk_id or "")
        has_parent = vid in parent_by_child
        has_children = len(children_by_parent.get(vid, [])) > 0
        if has_parent and has_children:
            return "intermediate"
        if has_children:
            return "root"
        return "leaf"

    def lineage_depth_from_root(vdisk_id: str):
        cur = str(vdisk_id or "")
        if not cur:
            return 0
        depth = 0
        seen = set()
        while cur and cur in parent_by_child and cur not in seen:
            seen.add(cur)
            cur = str(parent_by_child.get(cur) or "")
            depth += 1
        return depth
    containers = parse_ncli_containers_detailed(sections.get("===NCLI_CTR_START===", ""))
    vms = parse_ncli_vms(sections.get("===NCLI_VM_START===", ""))
    vgs = parse_ncli_volume_groups(sections.get("===NCLI_VG_START===", ""))
    usage_map = parse_curator_usage(sections.get("===CURATOR_START===", ""))
    chain_usage_map = parse_curator_chain_usage(sections.get("===CURATOR_CHAIN_USAGE_START===", ""))
    garbage_map = parse_curator_garbage_report(sections.get("===CURATOR_GARBAGE_START===", ""))
    sp_info = parse_ncli_storage_pool(sections.get("===NCLI_SP_START===", ""))

    vm_by_vdisk_id = {}
    vm_by_owner_key = {}
    for vm_data in vms.values():
        vm_name = vm_data.get("name")
        if not vm_name:
            continue
        vm_uuid = str(vm_data.get("uuid") or "").strip()
        if vm_uuid:
            vm_by_owner_key[vm_uuid] = vm_name
        for vid in vm_data.get("vdisk_ids", []):
            vm_by_vdisk_id[str(vid)] = vm_name
        for token in vm_data.get("vdisks", []):
            tail = str(token).split("::")[-1].strip()
            if tail:
                vm_by_vdisk_id[tail] = vm_name

    disk_uuid_to_vg = {}
    for _, vg in vgs.items():
        for disk_uuid in vg.get("disk_uuids", []):
            disk_uuid_to_vg[disk_uuid] = vg.get("name")

    chain_to_vdisk_ids = {}
    for vd in vdisks:
        cid = str(vd.get("chain_id") or "").strip()
        vid = str(vd.get("vdisk_id") or "").strip()
        if cid and vid:
            chain_to_vdisk_ids.setdefault(cid, [])
            if vid not in chain_to_vdisk_ids[cid]:
                chain_to_vdisk_ids[cid].append(vid)

    def compute_chain_shared_usage(chain_id: str, chain_vdisk_ids: list):
        """Compute shared usage for one chain. Caller applies family-level preconditions."""
        stats = chain_usage_map.get(chain_id, {})
        logical_live = int(stats.get("logical_live", 0) or 0)
        logical_clone = int(stats.get("logical_shared_clone", 0) or 0)
        logical_exclusive_snapshot = int(stats.get("logical_exclusive_snapshot", 0) or 0)
        physical_peg = int(stats.get("physical_peg", 0) or 0)
        exclusive_sum = sum(int(usage_map.get(str(vd_id), 0) or 0) for vd_id in chain_vdisk_ids)
        if logical_clone > 0:
            shared_bytes = (logical_clone * 2)
            source = "curator_chain_x2"
        elif len(chain_vdisk_ids) <= 1:
            shared_bytes = 0
            source = "single_vdisk_zero_clone_no_shared"
        else:
            # Snapshot-chain leftover is owned by Chain Snap Share; do not count it here.
            shared_bytes = 0
            source = "zero_clone_use_chain_snap_share"
        return {
            "logical_live": logical_live,
            "logical_shared_clone": logical_clone,
            "logical_exclusive_snapshot": logical_exclusive_snapshot,
            "physical_peg": physical_peg,
            "exclusive_sum": exclusive_sum,
            "shared_bytes": int(max(0, shared_bytes)),
            "source": source,
        }

    def chain_tree_family_all_to_remove(member_chain_ids: list) -> bool:
        """True only when the chain-tree family has vdisks and every one is to_remove."""
        family_vids = []
        for cid in member_chain_ids:
            family_vids.extend(chain_nodes.get(cid, ChainNode(chain_id=cid)).vdisk_ids)
        if not family_vids:
            return False
        return all(bool(vdisk_by_id.get(str(vid), {}).get("to_remove", False)) for vid in family_vids)

    # Build chain nodes first; shared usage is filled after chain-tree family checks.
    chain_nodes = {}
    for chain_id, chain_vdisk_ids in chain_to_vdisk_ids.items():
        stats = chain_usage_map.get(chain_id, {})
        chain_nodes[chain_id] = ChainNode(
            chain_id=chain_id,
            vdisk_ids=list(chain_vdisk_ids),
            logical_live=int(stats.get("logical_live", 0) or 0),
            logical_shared_clone=int(stats.get("logical_shared_clone", 0) or 0),
            logical_exclusive_snapshot=int(stats.get("logical_exclusive_snapshot", 0) or 0),
            physical_peg=int(stats.get("physical_peg", 0) or 0),
            shared_bytes=0,
            shared_formula_source="pending_family_precondition",
            shared_formula_terms={},
        )

    # Build chain graph edges.
    for vd in vdisks:
        child_chain = str(vd.get("chain_id") or "").strip()
        if not child_chain or child_chain not in chain_nodes:
            continue
        explicit_parent_chain = str(vd.get("parent_chain_id") or "").strip()
        parent_chain_candidates = []
        if explicit_parent_chain and explicit_parent_chain != child_chain:
            parent_chain_candidates.append(explicit_parent_chain)
        parent_vdisk_id = parent_by_child.get(str(vd.get("vdisk_id") or ""))
        if parent_vdisk_id:
            parent_vd = vdisk_by_id.get(str(parent_vdisk_id), {})
            inferred_parent_chain = str(parent_vd.get("chain_id") or "").strip()
            if inferred_parent_chain and inferred_parent_chain != child_chain:
                parent_chain_candidates.append(inferred_parent_chain)
        for parent_chain in parent_chain_candidates:
            if parent_chain not in chain_nodes:
                chain_nodes[parent_chain] = ChainNode(chain_id=parent_chain)
            chain_nodes[child_chain].parent_chain_ids.add(parent_chain)
            chain_nodes[parent_chain].child_chain_ids.add(child_chain)

    container_by_id = {str(c.get("id_short")): c for c in containers if c.get("id_short") is not None}
    vdisk_nodes = {}
    for vd in vdisks:
        vdisk_id = str(vd.get("vdisk_id") or "").strip()
        if not vdisk_id:
            continue
        chain_id = str(vd.get("chain_id") or "").strip()
        container_id = str(vd.get("container_id") or "").strip()
        is_snapshot = "Immutable" in str(vd.get("mutability_state", ""))
        is_to_remove = bool(vd.get("to_remove", False))
        is_in_recycle_bin = bool(vd.get("in_recycle_bin", False))
        nfs_file_name = str(vd.get("nfs_file_name") or "").strip()
        owner_id = str(vd.get("owner_id") or "").strip()
        vm_name = (
            vm_by_vdisk_id.get(vdisk_id)
            or vm_by_owner_key.get(owner_id)
            or vm_by_vdisk_id.get(str(vd.get("vdisk_name") or "").strip())
            or vm_by_vdisk_id.get(nfs_file_name)
        )
        mapped_vg = None
        vdisk_uuid = str(vd.get("vdisk_uuid") or "").strip()
        if vdisk_uuid and vdisk_uuid in disk_uuid_to_vg:
            mapped_vg = disk_uuid_to_vg[vdisk_uuid]
        elif nfs_file_name and nfs_file_name in disk_uuid_to_vg:
            mapped_vg = disk_uuid_to_vg[nfs_file_name]

        entity_type = "vdisk"
        entity_name = "VDisks"
        if is_in_recycle_bin:
            entity_type, entity_name = "recycle_bin", "Recycle Bin"
        elif is_to_remove:
            entity_type, entity_name = "pending_deletion", "Pending Deletion (to_remove)"
        elif is_snapshot:
            entity_type, entity_name = "snapshot", "Snapshots"
        elif vm_name:
            entity_type, entity_name = "vm", f"VM: {vm_name}"
        elif mapped_vg:
            entity_type, entity_name = "vg", f"VG: {mapped_vg}"

        vdisk_nodes[vdisk_id] = VdiskNode(
            vdisk_id=vdisk_id,
            chain_id=chain_id,
            container_id=container_id,
            parent_vdisk_id=parent_by_child.get(vdisk_id),
            parent_chain_id=(str(vd.get("parent_chain_id") or "").strip() or None),
            children_vdisk_ids=list(children_by_parent.get(vdisk_id, [])),
            exclusive_bytes=int(usage_map.get(vdisk_id, 0) or 0),
            entity_type=entity_type,
            entity_name=entity_name,
            vm_name=vm_name,
            vg_name=mapped_vg,
            is_snapshot=is_snapshot,
            is_to_remove=is_to_remove,
            is_in_recycle_bin=is_in_recycle_bin,
        )

    # Chain trees: root by chain_id where no parent chain exists.
    roots = [cid for cid, node in chain_nodes.items() if not node.parent_chain_ids]
    visited = set()
    chain_trees = []
    for root_chain_id in sorted(roots):
        if root_chain_id in visited:
            continue
        stack = [root_chain_id]
        members = []
        while stack:
            cid = stack.pop()
            if cid in visited:
                continue
            visited.add(cid)
            members.append(cid)
            stack.extend(sorted(chain_nodes[cid].child_chain_ids))
        leaves = [cid for cid in members if len([c for c in chain_nodes[cid].child_chain_ids if c in members]) == 0]

        # Precondition: if every vdisk in this chain-tree family is to_remove,
        # skip shared-usage calculation and move to the next family.
        if chain_tree_family_all_to_remove(members):
            for cid in members:
                node = chain_nodes[cid]
                node.shared_bytes = 0
                node.shared_formula_source = "skipped_all_family_to_remove"
                node.shared_formula_terms = {
                    "logical_live": int(node.logical_live or 0),
                    "logical_shared_clone": int(node.logical_shared_clone or 0),
                    "physical_peg": int(node.physical_peg or 0),
                    "exclusive_sum": 0,
                }
            chain_trees.append(
                ChainTree(
                    chain_tree_id=f"chain-tree-{root_chain_id}",
                    root_chain_id=root_chain_id,
                    member_chain_ids=sorted(members),
                    leaf_chain_ids=sorted(leaves),
                    selected_shared_chain_id=None,
                    selected_shared_bytes=0,
                    leaf_candidates=[],
                )
            )
            continue

        # At least one vdisk in the family is not to_remove: calculate shared usage.
        for cid in members:
            node = chain_nodes[cid]
            computed = compute_chain_shared_usage(cid, list(node.vdisk_ids))
            node.logical_live = int(computed["logical_live"])
            node.logical_shared_clone = int(computed["logical_shared_clone"])
            node.logical_exclusive_snapshot = int(computed["logical_exclusive_snapshot"])
            node.physical_peg = int(computed["physical_peg"])
            node.shared_bytes = int(computed["shared_bytes"])
            node.shared_formula_source = computed["source"]
            node.shared_formula_terms = {
                "logical_live": int(computed["logical_live"]),
                "logical_shared_clone": int(computed["logical_shared_clone"]),
                "physical_peg": int(computed["physical_peg"]),
                "exclusive_sum": int(computed["exclusive_sum"]),
            }

        leaf_candidates = [{"chain_id": cid, "shared_bytes": int(chain_nodes[cid].shared_bytes)} for cid in leaves]
        selected = max(leaf_candidates, key=lambda x: x["shared_bytes"]) if leaf_candidates else {"chain_id": None, "shared_bytes": 0}
        chain_trees.append(
            ChainTree(
                chain_tree_id=f"chain-tree-{root_chain_id}",
                root_chain_id=root_chain_id,
                member_chain_ids=sorted(members),
                leaf_chain_ids=sorted(leaves),
                selected_shared_chain_id=selected.get("chain_id"),
                selected_shared_bytes=int(selected.get("shared_bytes", 0)),
                leaf_candidates=leaf_candidates,
            )
        )

    container_graphs = {}
    for c in containers:
        container_id = str(c.get("id_short") or "")
        container_name = c.get("name", f"Container-{container_id}")
        try:
            rf = int(str(c.get("replication_factor") or "2").strip())
            if rf <= 0:
                rf = 2
        except Exception:
            rf = 2
        container_graphs[container_id] = ContainerGraph(
            container_id=container_id,
            container_name=container_name,
            replication_factor=rf,
        )

    for v in vdisk_nodes.values():
        cg = container_graphs.get(v.container_id)
        if not cg:
            continue
        cg.vdisk_ids.append(v.vdisk_id)
        cg.entity_groups.setdefault(v.entity_name, []).append(v.vdisk_id)

    for tree in chain_trees:
        member_containers = set()
        for cid in tree.member_chain_ids:
            for vid in chain_nodes.get(cid, ChainNode(chain_id=cid)).vdisk_ids:
                vnode = vdisk_nodes.get(str(vid))
                if vnode:
                    member_containers.add(vnode.container_id)
        for container_id in member_containers:
            cg = container_graphs.get(container_id)
            if cg:
                cg.chain_trees.append(tree)

    container_nodes = []
    total_physical = 0
    for container_id, cg in container_graphs.items():
        c = container_by_id.get(container_id, {})
        container_children = []
        c_total = 0

        for group_name, group_vdisk_ids in cg.entity_groups.items():
            group_nodes = []
            group_total = 0
            for vid in group_vdisk_ids:
                vd = vdisk_by_id.get(vid, {})
                vnode = vdisk_nodes.get(vid)
                if not vnode:
                    continue
                chain_node = chain_nodes.get(vnode.chain_id, ChainNode(chain_id=vnode.chain_id))
                params_reserved = int(((vd.get("params") or {}).get("total_reserved_capacity", 0)) or 0)
                has_hint_total_reserved_capacity = "hint_total_reserved_capacity" in vd
                thick_raw = params_reserved if (params_reserved > 0 and not has_hint_total_reserved_capacity) else 0
                thick_scaled = thick_raw * cg.replication_factor if thick_raw > 0 else 0
                primary_usage = thick_scaled if thick_raw > 0 else vnode.exclusive_bytes
                group_total += primary_usage
                c_total += primary_usage
                group_nodes.append({
                    **vd,
                    "name": str(vid),
                    "value": primary_usage if primary_usage > 0 else 1,
                    "real_bytes": primary_usage,
                    "formatted_size": format_bytes(primary_usage),
                    "display_source": "thick_prov_total_reserved_capacity_x_rf" if thick_raw > 0 else "curator_cli",
                    "is_thick_prov_vdisk": thick_raw > 0,
                    "thick_prov_raw_bytes": thick_raw,
                    "thick_prov_vdisk_bytes": thick_scaled,
                    "is_in_recycle_bin": vnode.is_in_recycle_bin,
                    "mapped_vm_name": vnode.vm_name,
                    "mapped_vg_name": vnode.vg_name,
                    "mapped_entity_name": group_name,
                    "parent_vdisk_id": vnode.parent_vdisk_id,
                    "children_vdisk_ids": sorted(list(vnode.children_vdisk_ids), key=lambda x: int(x) if str(x).isdigit() else str(x)),
                    "lineage_summary": {
                        "current_vdisk_id": str(vnode.vdisk_id),
                        "lineage_root_vdisk_id": lineage_root(vnode.vdisk_id),
                        "depth_from_root": lineage_depth_from_root(vnode.vdisk_id),
                        "parent_vdisk_id": vnode.parent_vdisk_id,
                        "children_vdisk_ids": sorted(list(vnode.children_vdisk_ids), key=lambda x: int(x) if str(x).isdigit() else str(x)),
                        "lineage_role": lineage_role(vnode.vdisk_id),
                    },
                    "chain_stats": {
                        "logical_exclusive": int(chain_node.shared_formula_terms.get("exclusive_sum", 0) or 0),
                        "logical_live": int(chain_node.logical_live or 0),
                        "logical_shared_clone": int(chain_node.logical_shared_clone or 0),
                        "logical_exclusive_snapshot": int(chain_node.logical_exclusive_snapshot or 0),
                        "physical_peg": int(chain_node.physical_peg or 0),
                    },
                    "shared_formula_source": chain_node.shared_formula_source,
                    "shared_formula_terms": chain_node.shared_formula_terms,
                })
            group_nodes.sort(key=lambda x: int(x.get("real_bytes", 0) or 0), reverse=True)
            container_children.append({
                "name": group_name,
                "aggregate_exclusive_bytes": group_total,
                "formatted_size": format_bytes(group_total),
                "children": group_nodes,
            })

        shared_storage_nodes = []
        shared_by_family_key = {}
        for tree in cg.chain_trees:
            selected_chain_id = tree.selected_shared_chain_id
            if not selected_chain_id:
                continue
            selected_chain = chain_nodes.get(selected_chain_id)
            if not selected_chain or selected_chain.shared_bytes <= 0:
                continue

            # lineage_id is the unique shared-storage identifier / highlight key.
            lineage_id = None
            for cid in (tree.member_chain_ids or []):
                for vid in chain_nodes.get(cid, ChainNode(chain_id=cid)).vdisk_ids:
                    vd = vdisk_by_id.get(str(vid), {})
                    lid = str(vd.get("lineage_id") or "").strip()
                    if lid:
                        lineage_id = lid
                        break
                if lineage_id:
                    break
            if not lineage_id:
                lineage_id = str(selected_chain_id)

            shared_clone_usage = int(
                (selected_chain.shared_formula_terms or {}).get("logical_shared_clone", 0)
                or selected_chain.logical_shared_clone
                or 0
            )
            candidate = {
                "name": lineage_id,
                # Synthetic aggregate node: do not reuse a real vdisk_id.
                "vdisk_id": None,
                "lineage_id": lineage_id,
                "shared_clone_usage_bytes": shared_clone_usage,
                "chain_id": selected_chain_id,
                "root_chain_id": tree.root_chain_id,
                "chain_tree_id": tree.chain_tree_id,
                "member_chain_ids": tree.member_chain_ids,
                "leaf_chain_ids": tree.leaf_chain_ids,
                "leaf_candidates": tree.leaf_candidates,
                "selected_shared_chain_id": selected_chain_id,
                "selected_shared_bytes": int(tree.selected_shared_bytes),
                "is_shared_parent_vdisk": True,
                "is_dummy_lineage_root": False,
                "value": int(tree.selected_shared_bytes),
                "real_bytes": int(tree.selected_shared_bytes),
                "shared_storage_bytes": int(tree.selected_shared_bytes),
                "shared_storage_curator_estimated_bytes": int(tree.selected_shared_bytes),
                "shared_formula_source": selected_chain.shared_formula_source,
                "shared_formula_terms": selected_chain.shared_formula_terms,
                "display_source": selected_chain.shared_formula_source,
                "formatted_size": format_bytes(int(tree.selected_shared_bytes)),
                "container_name": cg.container_name,
            }

            # Same lineage_id: keep max shared-clone usage.
            existing = shared_by_family_key.get(lineage_id)
            if existing is None:
                shared_by_family_key[lineage_id] = candidate
            else:
                existing_clone = int(existing.get("shared_clone_usage_bytes", 0) or 0)
                existing_shared = int(existing.get("selected_shared_bytes", 0) or 0)
                cand_shared = int(candidate.get("selected_shared_bytes", 0) or 0)
                if (
                    shared_clone_usage > existing_clone
                    or (shared_clone_usage == existing_clone and cand_shared > existing_shared)
                ):
                    shared_by_family_key[lineage_id] = candidate

        shared_storage_nodes = list(shared_by_family_key.values())
        shared_storage_nodes.sort(key=lambda x: int(x.get("real_bytes", 0) or 0), reverse=True)
        shared_total = sum(int(n.get("real_bytes", 0) or 0) for n in shared_storage_nodes)
        if shared_storage_nodes:
            container_children.append({
                "name": "Shared Storage",
                "aggregate_exclusive_bytes": shared_total,
                "formatted_size": format_bytes(shared_total),
                "children": shared_storage_nodes,
            })

        snap_share_nodes = []
        seen_snap_chains = set()
        for vid in cg.vdisk_ids:
            vnode = vdisk_nodes.get(str(vid))
            if not vnode or not vnode.chain_id:
                continue
            cid = str(vnode.chain_id)
            if cid in seen_snap_chains:
                continue
            seen_snap_chains.add(cid)
            chain_vids = chain_to_vdisk_ids.get(cid, [])
            computed = compute_chain_snap_share(cid, chain_vids, chain_usage_map, usage_map)
            if int(computed.get("snap_share", 0) or 0) <= 0:
                continue
            snap_share_nodes.append(
                build_chain_snap_share_leaf(cid, chain_vids, computed, cg.container_name)
            )
        snap_share_nodes.sort(key=lambda x: int(x.get("real_bytes", 0) or 0), reverse=True)
        snap_share_total = sum(int(n.get("real_bytes", 0) or 0) for n in snap_share_nodes)
        if snap_share_nodes:
            container_children.append({
                "name": "Chain Snap Share",
                "aggregate_exclusive_bytes": snap_share_total,
                "formatted_size": format_bytes(snap_share_total),
                "children": snap_share_nodes,
            })

        garbage_info = garbage_map.get(str(container_id), {}) or {}
        partial_extents_bytes = int(garbage_info.get("partial_extents_bytes", 0) or 0)
        total_garbage_bytes = int(garbage_info.get("total_garbage_wo_peg_bytes", 0) or 0)
        if partial_extents_bytes > 0:
            container_children.append({
                "name": "Partial Extents",
                "aggregate_exclusive_bytes": partial_extents_bytes,
                "formatted_size": format_bytes(partial_extents_bytes),
                "children": [{
                    "name": "Partial Extents",
                    "is_partial_extents_block": True,
                    "container_id": container_id,
                    "container_name": cg.container_name,
                    "value": partial_extents_bytes,
                    "real_bytes": partial_extents_bytes,
                    "formatted_size": format_bytes(partial_extents_bytes),
                    "display_source": "curator_display_garbage_report",
                }],
            })
        if total_garbage_bytes > 0:
            container_children.append({
                "name": "Total Garbage w/o PEG",
                "aggregate_exclusive_bytes": total_garbage_bytes,
                "formatted_size": format_bytes(total_garbage_bytes),
                "children": [{
                    "name": "Total Garbage w/o PEG",
                    "is_total_garbage_block": True,
                    "container_id": container_id,
                    "container_name": cg.container_name,
                    "value": total_garbage_bytes,
                    "real_bytes": total_garbage_bytes,
                    "formatted_size": format_bytes(total_garbage_bytes),
                    "display_source": "curator_display_garbage_report",
                }],
            })

        explicit_res_bytes = int(c.get("explicit_res_logical_bytes", 0) or 0)
        explicit_res_scaled_bytes = explicit_res_bytes * cg.replication_factor
        other_total = c_total + shared_total + snap_share_total
        explicit_residual_bytes = explicit_res_scaled_bytes - other_total
        if explicit_residual_bytes > 0:
            container_children.append({
                "name": "Reserved Available Space",
                "aggregate_exclusive_bytes": explicit_residual_bytes,
                "formatted_size": format_bytes(explicit_residual_bytes),
                "children": [{
                    "name": "Reserved Available Space",
                    "is_explicit_reserve_block": True,
                    "container_name": cg.container_name,
                    "value": explicit_residual_bytes,
                    "real_bytes": explicit_residual_bytes,
                    "raw_explicit_reserve_bytes": explicit_res_bytes,
                    "scaled_explicit_reserve_bytes": explicit_res_scaled_bytes,
                    "other_container_total_bytes": other_total,
                    "formula": "reserved_available_space_equals_explicit_res_logical_x_rf_minus_all_container_usage",
                    "scaled_by_replication_factor": True,
                    "display_source": "ncli_container_logical_residual",
                    "formatted_size": format_bytes(explicit_residual_bytes),
                }]
            })

        c_total_with_shared = other_total + max(0, explicit_residual_bytes)
        total_physical += c_total_with_shared
        container_children.sort(key=lambda g: (-int(g.get("aggregate_exclusive_bytes", 0) or 0), str(g.get("name", ""))))
        container_nodes.append({
            "name": cg.container_name,
            "container_id": container_id,
            "container_vdisk_count": len(cg.vdisk_ids),
            "aggregate_exclusive_bytes": c_total_with_shared,
            "formatted_size": format_bytes(c_total_with_shared),
            "container_used_space_physical": c.get("used_space_physical"),
            "container_used_space_physical_bytes": c.get("used_space_physical_bytes", 0),
            "container_free_space_physical": c.get("free_space_physical"),
            "container_max_capacity_physical": c.get("max_capacity_physical"),
            "explicit_res_logical": c.get("explicit_res_logical"),
            "explicit_res_logical_bytes": explicit_res_bytes,
            "explicit_res_logical_scaled_bytes": explicit_res_scaled_bytes,
            "explicit_res_logical_residual_bytes": max(0, explicit_residual_bytes),
            "thick_prov_logical": c.get("thick_prov_logical"),
            "thick_prov_logical_bytes": c.get("thick_prov_logical_bytes", 0),
            "replication_factor": cg.replication_factor,
            "entity_groups": [{"name": n, "vdisk_ids": ids} for n, ids in cg.entity_groups.items()],
            "chain_trees": [t.__dict__ for t in cg.chain_trees],
            "children": container_children,
        })

    container_nodes.sort(key=lambda x: int(x.get("aggregate_exclusive_bytes", 0) or 0), reverse=True)
    sp_capacity = sp_info.get("capacity_bytes", 0) or sp_info.get("used_bytes", 0)
    sp_used = sp_info.get("used_bytes", total_physical)
    sp_free = sp_info.get("free_bytes", max(sp_capacity - sp_used, 0))

    return {
        "status": "success",
        "collector_timing": collector_timing,
        "model_version": "chain_v2",
        "tree": {
            "name": f"Storage Pool: {sp_info.get('name', 'Nutanix_SP')}",
            "formatted_size": format_bytes(sp_capacity),
            "children": [
                {
                    "name": f"Used Space ({format_bytes(sp_used)})",
                    "formatted_size": format_bytes(sp_used),
                    "children": container_nodes
                },
                {
                    "name": f"Free Space ({format_bytes(sp_free)})",
                    "value": sp_free,
                    "is_free": True,
                    "formatted_size": format_bytes(sp_free)
                }
            ]
        }
    }


def process_raw_logs(raw_output: str, run_id: str = "run-unknown"):
    sections = extract_log_sections(raw_output)
    if sections.get("===CURATOR_START===") and sections.get("===VDISK_CFG_START==="):
        return process_container_chain_graph_logs(sections)

    vdisk_log = sections.get("===VDISK_CFG_START===", "")
    curator_chain_log = sections.get("===CURATOR_CHAIN_USAGE_START===", "")
    snapshot_chain_ids_log = sections.get("===SNAPSHOT_TREE_CHAIN_IDS_START===", "")
    
    if not vdisk_log or "vdisk_id:" not in vdisk_log:
        raise Exception("No VDisk configuration entries found in CVM output.")

    vdisks = parse_vdisk_configure_printer(vdisk_log)
    chain_usage_map = parse_curator_chain_usage(curator_chain_log) if curator_chain_log else {}
    explicit_chain_vdisks = parse_snapshot_tree_chain_ids(snapshot_chain_ids_log) if snapshot_chain_ids_log else {}
    usage_map = parse_curator_usage(sections.get("===CURATOR_START===", ""))
    chain_map = parse_snapshot_tree_printer(sections.get("===SNAPSHOT_TREE_START===", ""))
    vms = parse_ncli_vms(sections.get("===NCLI_VM_START===", ""))
    vgs = parse_ncli_volume_groups(sections.get("===NCLI_VG_START===", ""))
    ctr_map = parse_ncli_containers(sections.get("===NCLI_CTR_START===", ""))
    ctr_name_to_id = {v: k for k, v in ctr_map.items()}
    sp_info = parse_ncli_storage_pool(sections.get("===NCLI_SP_START===", ""))
    garbage_map = parse_curator_garbage_report(sections.get("===CURATOR_GARBAGE_START===", ""))


    disk_uuid_to_vg = {}
    for vg_uuid, vg in vgs.items():
        for disk_uuid in vg.get("disk_uuids", []):
            disk_uuid_to_vg[disk_uuid] = vg["name"]

    vdisk_to_vm = {}
    for vm_key, vm_data in vms.items():
        vm_name = vm_data["name"]
        vm_uuid = vm_data.get("uuid")
        if vm_uuid: vdisk_to_vm[vm_uuid] = vm_name
        for vdisk_str in vm_data.get("vdisks", []):
            clean_vdisk = vdisk_str.split("::")[-1].strip()
            if clean_vdisk: vdisk_to_vm[clean_vdisk] = vm_name

    vdisk_to_chain = {vd.get("vdisk_id"): vd.get("chain_id") for vd in vdisks if vd.get("chain_id")}
    for vd in vdisks:
        if vd.get("chain_id") and not vd.get("parent_chain_id"):
            parent_vid = vd.get("parent_vdisk_id") or vd.get("clone_source_vdisk_id")
            if parent_vid and parent_vid in vdisk_to_chain:
                resolved_pcid = vdisk_to_chain[parent_vid]
                if resolved_pcid != vd.get("chain_id"):
                    vd["parent_chain_id"] = resolved_pcid

    vdisk_map = {vd.get("vdisk_id"): vd for vd in vdisks}

    # --- STEP 1: Build Core Chain Logic & Properties ---
    chains = {}
    
    for cid, v_ids in explicit_chain_vdisks.items():
        chains[cid] = {
            "chain_id": cid,
            "isChildren": False,
            "isParent": False,
            "parent_chain_id": None,
            "children_chain_ids": [],
            "vdisk_ids": list(v_ids),
            "isCalculated": False,
            "container_id": None
        }

    for vd in vdisks:
        cid = vd.get("chain_id")
        vid = vd.get("vdisk_id")
        if cid:
            if cid not in chains:
                chains[cid] = {
                    "chain_id": cid, "isChildren": False, "isParent": False, 
                    "parent_chain_id": None, "children_chain_ids": [], 
                    "vdisk_ids": [], "isCalculated": False, "container_id": None
                }
            if vid not in chains[cid]["vdisk_ids"]:
                chains[cid]["vdisk_ids"].append(vid)

    for cid, c_node in list(chains.items()):
        for vid in c_node["vdisk_ids"]:
            vd = vdisk_map.get(vid)
            if vd:
                if not c_node["container_id"]:
                    c_node["container_id"] = vd.get("container_id", "Unknown")
                    
                pcid = vd.get("parent_chain_id")
                if pcid:
                    c_node["isChildren"] = True
                    c_node["parent_chain_id"] = pcid
                    
                    if pcid not in chains:
                        chains[pcid] = {
                            "chain_id": pcid, "isChildren": False, "isParent": False, 
                            "parent_chain_id": None, "children_chain_ids": [], 
                            "vdisk_ids": [], "isCalculated": False, "container_id": vd.get("container_id", "Unknown")
                        }
                    
                    chains[pcid]["isParent"] = True
                    if cid not in chains[pcid]["children_chain_ids"]:
                        chains[pcid]["children_chain_ids"].append(cid)


    # --- STEP 2: Shared Clone Calculation Algorithm ---
    container_shared_nodes = {}
    shared_family_vdisks = set()
    shared_family_chain_ids = set()
    
    for cid, c_node in chains.items():
        stats = chain_usage_map.get(cid, {})
        logical_live = int(stats.get("logical_live", 0) or 0)
        logical_clone = stats.get("logical_shared_clone", 0)
        physical_peg = stats.get("physical_peg", 0)
        chain_vdisks = set(c_node.get("vdisk_ids", []))
        exclusive_sum = sum(int(usage_map.get(str(vd_id), 0) or 0) for vd_id in chain_vdisks)
        if logical_clone > 0:
            shared_size = (logical_clone * 2)
            shared_formula_source = "curator_chain_x2"
        elif len(chain_vdisks) <= 1:
            shared_size = 0
            shared_formula_source = "single_vdisk_zero_clone_no_shared"
        else:
            # Snapshot-chain leftover is owned by Chain Snap Share; do not count it here.
            shared_size = 0
            shared_formula_source = "zero_clone_use_chain_snap_share"
        if shared_size <= 0:
            continue

        shared_family_chain_ids.add(cid)
        shared_family_vdisks.update(chain_vdisks)

        c_id = c_node.get("container_id") or "Unknown"
        c_name = ctr_map.get(str(c_id), f"Container-{c_id}")
        if c_name not in container_shared_nodes:
            container_shared_nodes[c_name] = []
        is_rootless_chain = (not bool(c_node.get("parent_chain_id"))) and (
            shared_formula_source == "snapshot_chain_live2_peg_minus_exclusive_sum"
        )

        container_shared_nodes[c_name].append({
            "name": f"Chain: {cid}",
            "chain_id": cid,
            "is_shared_clone_block": True,
            "is_dummy_lineage_root": is_rootless_chain,
            "value": shared_size,
            "physical_size": shared_size,
            "logical_clone_bytes": logical_clone,
            "logical_live_bytes": logical_live,
            "total_physical_peg_bytes": physical_peg,
            "shared_formula_source": shared_formula_source,
            "shared_formula_terms": {
                "logical_live": logical_live,
                "logical_shared_clone": int(logical_clone or 0),
                "physical_peg": int(physical_peg or 0),
                "exclusive_sum": int(exclusive_sum),
            },
            "formatted_size": format_bytes(shared_size),
            "formatted_logical_clone": format_bytes(logical_clone),
            "formatted_logical_live": format_bytes(logical_live),
            "formatted_total_peg": format_bytes(physical_peg),
            "vdisk_ids": sorted(list(chain_vdisks))
        })

    container_snap_share_nodes = {}
    for cid, c_node in chains.items():
        chain_vdisks = list(c_node.get("vdisk_ids", []))
        computed = compute_chain_snap_share(cid, chain_vdisks, chain_usage_map, usage_map)
        if int(computed.get("snap_share", 0) or 0) <= 0:
            continue
        c_id = c_node.get("container_id") or "Unknown"
        c_name = ctr_map.get(str(c_id), f"Container-{c_id}")
        container_snap_share_nodes.setdefault(c_name, []).append(
            build_chain_snap_share_leaf(cid, chain_vdisks, computed, c_name)
        )

    # --- STEP 3: Exclusive VDisk Usage Calculation ---
    container_tree = {}
    NOMINAL_LAYOUT_BYTES = 10 * 1024 * 1024

    for vd in vdisks:
        cont_id = vd.get("container_id", "Unknown")
        c_name = ctr_map.get(str(cont_id), f"Container-{cont_id}")
        
        vdisk_id = vd.get("vdisk_id")
        owner_vm_id = vd.get("owner_id")
        vdisk_name = vd.get("vdisk_name", "")
        nfs_file_name = vd.get("nfs_file_name", "")
        is_to_remove = bool(vd.get("to_remove", False))
        is_in_recycle_bin = bool(vd.get("in_recycle_bin", False))
        is_snapshot = "Immutable" in vd.get("mutability_state", "")

        mapped_vm = None
        if owner_vm_id and owner_vm_id in vdisk_to_vm: mapped_vm = vdisk_to_vm[owner_vm_id]
        elif owner_vm_id and owner_vm_id in vms: mapped_vm = vms[owner_vm_id]["name"]
        elif vdisk_name and vdisk_name in vdisk_to_vm: mapped_vm = vdisk_to_vm[vdisk_name]
        elif vdisk_id and str(vdisk_id) in vdisk_to_vm: mapped_vm = vdisk_to_vm[str(vdisk_id)]
        else:
            for vm_uuid_key, vm_data in vms.items():
                for v_str in vm_data.get("vdisks", []):
                    if (vdisk_name and vdisk_name in v_str) or (vdisk_id and str(vdisk_id) in v_str):
                        mapped_vm = vm_data["name"]
                        break
                if mapped_vm: break

        mapped_vg = None
        vg_resolution_method = None
        vdisk_uuid = str(vd.get("vdisk_uuid") or "").strip()
        if vdisk_uuid and vdisk_uuid in disk_uuid_to_vg:
            mapped_vg = disk_uuid_to_vg[vdisk_uuid]
            vg_resolution_method = "vdisk_uuid"
        elif nfs_file_name in disk_uuid_to_vg:
            mapped_vg = disk_uuid_to_vg[nfs_file_name]
            vg_resolution_method = "nfs_file_name_uuid"

        if is_in_recycle_bin:
            mapped_entity = "Recycle Bin"
        elif is_to_remove:
            mapped_entity = "Pending Deletion (to_remove)"
        elif is_snapshot:
            mapped_entity = "Snapshots"
        elif mapped_vm:
            mapped_entity = f"VM: {mapped_vm}"
        elif mapped_vg:
            mapped_entity = f"VG: {mapped_vg}"
        else:
            mapped_entity = "Other VDisks"

        if c_name not in container_tree:
            container_tree[c_name] = {}
        if mapped_entity not in container_tree[c_name]:
            container_tree[c_name][mapped_entity] = []

        exclusive_bytes = usage_map.get(str(vdisk_id), 0)
        node_data = vd.copy()
        node_data.update({
            "name": f"VDisk-{vdisk_id}" + (" (To Remove)" if is_to_remove else ""),
            "chain_info": chain_map.get(str(vdisk_id), []),
            "value": exclusive_bytes if exclusive_bytes > 0 else NOMINAL_LAYOUT_BYTES,
            "real_bytes": exclusive_bytes,
            "formatted_size": format_bytes(exclusive_bytes),
            "is_in_recycle_bin": is_in_recycle_bin,
            "mapped_vm_name": mapped_vm,
            "mapped_vg_name": mapped_vg,
            "mapped_entity_name": mapped_entity,
            "vg_resolution_method": vg_resolution_method,
        })
        container_tree[c_name][mapped_entity].append(node_data)

    # --- STEP 4: Aggregate Final JSON Payload ---
    container_nodes = []
    all_c_names = set(container_tree.keys()).union(container_shared_nodes.keys()).union(container_snap_share_nodes.keys())

    for c_name in all_c_names:
        entities = container_tree.get(c_name, {})
        c_total_exclusive = 0
        container_vdisk_ids = set()
        
        shared_clone_blocks = container_shared_nodes.get(c_name, [])
        if shared_clone_blocks:
            entities["Shared Clones"] = shared_clone_blocks
        snap_share_blocks = container_snap_share_nodes.get(c_name, [])
        if snap_share_blocks:
            entities["Chain Snap Share"] = snap_share_blocks

        c_id = ctr_name_to_id.get(c_name)
        garbage_info = garbage_map.get(str(c_id), {}) or {} if c_id is not None else {}
        partial_extents_bytes = int(garbage_info.get("partial_extents_bytes", 0) or 0)
        total_garbage_bytes = int(garbage_info.get("total_garbage_wo_peg_bytes", 0) or 0)
        if partial_extents_bytes > 0:
            entities["Partial Extents"] = [{
                "name": "Partial Extents",
                "is_partial_extents_block": True,
                "container_id": c_id,
                "container_name": c_name,
                "value": partial_extents_bytes,
                "real_bytes": partial_extents_bytes,
                "formatted_size": format_bytes(partial_extents_bytes),
                "display_source": "curator_display_garbage_report",
            }]
        if total_garbage_bytes > 0:
            entities["Total Garbage w/o PEG"] = [{
                "name": "Total Garbage w/o PEG",
                "is_total_garbage_block": True,
                "container_id": c_id,
                "container_name": c_name,
                "value": total_garbage_bytes,
                "real_bytes": total_garbage_bytes,
                "formatted_size": format_bytes(total_garbage_bytes),
                "display_source": "curator_display_garbage_report",
            }]

        e_nodes = []
        for e_name, v_list in entities.items():
            if e_name == "Shared Clones":
                e_exclusive = sum(node["physical_size"] for node in v_list)
            else:
                e_exclusive = sum(v.get("real_bytes", 0) for v in v_list)
                for v in v_list:
                    vid = v.get("vdisk_id")
                    if vid is not None and str(vid).strip():
                        container_vdisk_ids.add(str(vid))

            c_total_exclusive += e_exclusive
            e_nodes.append({
                "name": e_name,
                "aggregate_exclusive_bytes": e_exclusive,
                "formatted_size": format_bytes(e_exclusive),
                "children": v_list
            })
        e_nodes.sort(
            key=lambda g: (
                -int(g.get("aggregate_exclusive_bytes", 0) or 0),
                str(g.get("name", ""))
            )
        )

        container_nodes.append({
            "name": c_name,
            "container_id": ctr_name_to_id.get(c_name),
            "container_vdisk_count": len(container_vdisk_ids),
            "aggregate_exclusive_bytes": c_total_exclusive,
            "formatted_size": format_bytes(c_total_exclusive),
            "children": e_nodes
        })

    sp_capacity = sp_info.get("capacity_bytes", 0)
    sp_used = sp_info.get("used_bytes", 0)
    sp_free = sp_info.get("free_bytes", 0)

    if sp_capacity == 0:
        sp_capacity = sp_used

    collector_timing = {}
    try:
        collector_timing = json.loads(sections.get("===COLLECTOR_TIMING_START===", "") or "{}")
    except Exception:
        collector_timing = {}
    return {
        "status": "success", 
        "collector_timing": collector_timing,
        "tree": {
            "name": f"Storage Pool: {sp_info.get('name', 'Nutanix_SP')}",
            "formatted_size": format_bytes(sp_capacity),
            "children": [
                {
                    "name": f"Used Space ({format_bytes(sp_used)})",
                    "formatted_size": format_bytes(sp_used),
                    "children": container_nodes
                },
                {
                    "name": f"Free Space ({format_bytes(sp_free)})",
                    "value": sp_free,
                    "is_free": True,
                    "formatted_size": format_bytes(sp_free)
                }
            ]
        }
    }

@app.get("/")
def read_root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(
            status_code=404, 
            detail=f"Frontend file not found at '{index_path}'."
        )
    return FileResponse(index_path)


@app.get("/api/offline-script")
def download_offline_script():
    script_path = os.path.join(PROJECT_ROOT, "collect_offline_log.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail=f"Offline script not found at '{script_path}'.")
    return FileResponse(
        script_path,
        media_type="text/x-python",
        filename="collect_offline_log.py",
    )

@app.post("/api/scan")
def scan_cvm(req: ScanRequest):
    try:
        collector = CVMCollector(host=req.cvm_ip, username=req.username, password=req.password)
        raw_output = collector.fetch_all_cvm_data()
        persist_raw_cvm_output(raw_output)
        return process_raw_logs(raw_output, run_id="live-ssh")
    except Exception as e:
        logger.error(f"SSH Scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/start")
def scan_cvm_start(req: ScanRequest):
    _cleanup_expired_scan_jobs()
    scan_id = str(uuid.uuid4())
    now = time.time()
    with scan_jobs_lock:
        scan_jobs[scan_id] = {
            "scan_id": scan_id,
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "events": [],
            "next_seq": 1,
            "result": None,
            "error": None,
        }
    _publish_scan_event(scan_id, "status", {"message": "Scan queued."})
    worker = threading.Thread(target=_run_scan_job, args=(scan_id, req), daemon=True)
    worker.start()
    return {"scan_id": scan_id}


@app.get("/api/scan/events/{scan_id}")
def scan_cvm_events(scan_id: str):
    _cleanup_expired_scan_jobs()
    with scan_jobs_lock:
        if scan_id not in scan_jobs:
            raise HTTPException(status_code=404, detail="scan_id not found or expired")

    def event_stream():
        last_seq = 0
        while True:
            payloads = []
            done = False
            with scan_jobs_lock:
                job = scan_jobs.get(scan_id)
                if not job:
                    break
                payloads = [e for e in job.get("events", []) if int(e.get("seq", 0)) > last_seq]
                status = job.get("status")
                error = job.get("error")
                if payloads:
                    last_seq = max(int(e.get("seq", 0)) for e in payloads)
                done = status in ("done", "error")
            for payload in payloads:
                evt = payload.get("event", "status")
                body = json.dumps(payload, ensure_ascii=True)
                yield f"event: {evt}\ndata: {body}\n\n"
            if done:
                break
            time.sleep(SCAN_EVENT_POLL_SEC)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/scan/result/{scan_id}")
def scan_cvm_result(scan_id: str):
    _cleanup_expired_scan_jobs()
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="scan_id not found or expired")
        status = job.get("status")
        if status == "done":
            return job.get("result")
        if status == "error":
            raise HTTPException(status_code=500, detail=job.get("error") or "scan failed")
        return {"status": status}

@app.post("/api/upload")
async def upload_offline_log(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        return process_raw_logs(contents.decode("utf-8", errors="ignore"), run_id=f"offline-single:{file.filename}")
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process offline file: {str(e)}")

