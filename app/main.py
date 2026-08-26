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
    parse_ncli_vms,
    parse_ncli_volume_groups,
    parse_ncli_storage_pool,
    parse_ncli_containers,
    parse_snapshot_tree_chain_ids,
    parse_ncli_containers_detailed,
    parse_nfs_ls_sections,
    parse_nfs_ls_sections_detailed,
    parse_vdisk_map_by_nfs,
)

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

def extract_log_sections(raw_output: str) -> dict:
    headers = [
        "===VDISK_CFG_START===", "===NCLI_VM_START===", "===NCLI_VG_START===",
        "===NCLI_SP_START===", "===NCLI_CTR_START===", "===SNAPSHOT_TREE_START===",
        "===SNAPSHOT_TREE_CHAIN_IDS_START===", "===CURATOR_START===", "===CURATOR_CHAIN_USAGE_START===",
        "===NFS_LS_START===", "===COLLECTOR_TIMING_START===",
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
            shared_bytes = (logical_clone * 2) + physical_peg
            source = "curator_chain_x2"
        elif len(chain_vdisk_ids) <= 1:
            shared_bytes = 0
            source = "single_vdisk_zero_clone_no_shared"
        else:
            shared_bytes = (logical_live * 2) + physical_peg - exclusive_sum
            source = "snapshot_chain_live2_peg_minus_exclusive_sum"
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
            is_snapshot = "Immutable" in str(vd.get("mutability_state", ""))
            node["is_to_remove"] = is_to_remove
            if is_to_remove:
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
            added_to_shared_root = False
            if resolved_parent_vdisk_id:
                immediate_parent_id = str(resolved_parent_vdisk_id)
                parent_vd = vdisk_by_id.get(immediate_parent_id, {})
                root_parent_id = lineage_root(immediate_parent_id)
                is_snapshot_same_chain = is_same_chain_snapshot_continuation(vd, parent_vd)
                if has_shared_signal and not is_snapshot_same_chain:
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
                    node["classification_reason"] = "shared_clone_lineage"
                    added_to_shared_root = True
                elif is_snapshot_same_chain:
                    node["classification_reason"] = "snapshot_same_chain_excluded_from_shared"
            elif (
                has_shared_signal
                and chain_id
                and not chain_has_parent_chain.get(chain_id, False)
                and chain_shared.get("source") == "snapshot_chain_live2_peg_minus_exclusive_sum"
            ):
                synthetic_root_id = f"dummy-root-chain-{chain_id}"
                child_shared_primary = curator_shared_estimate
                if synthetic_root_id not in shared_root_nodes:
                    shared_root_nodes[synthetic_root_id] = {
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
                else:
                    if child_shared_primary >= int(shared_root_nodes[synthetic_root_id].get("max_primary_shared_bytes", 0)):
                        shared_root_nodes[synthetic_root_id]["shared_formula_source"] = chain_shared.get("source")
                        shared_root_nodes[synthetic_root_id]["shared_formula_terms"] = chain_shared.get("terms", {})
                        shared_root_nodes[synthetic_root_id]["anchor_vdisk_id"] = vdisk_id
                    shared_root_nodes[synthetic_root_id]["max_curator_shared_estimated_bytes"] = max(
                        shared_root_nodes[synthetic_root_id]["max_curator_shared_estimated_bytes"], curator_shared_estimate
                    )
                    shared_root_nodes[synthetic_root_id]["max_primary_shared_bytes"] = max(
                        shared_root_nodes[synthetic_root_id]["max_primary_shared_bytes"], child_shared_primary
                    )
                    shared_root_nodes[synthetic_root_id]["child_vdisk_ids"].append(vdisk_id)
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

def process_raw_logs(raw_output: str, run_id: str = "run-unknown"):
    sections = extract_log_sections(raw_output)
    if sections.get("===NFS_LS_START===") and sections.get("===CURATOR_START===") and sections.get("===VDISK_CFG_START==="):
        return process_container_centric_logs(sections)

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
            shared_size = (logical_clone * 2) + physical_peg
            shared_formula_source = "curator_chain_x2"
        elif len(chain_vdisks) <= 1:
            shared_size = 0
            shared_formula_source = "single_vdisk_zero_clone_no_shared"
        else:
            shared_size = (logical_live * 2) + physical_peg - exclusive_sum
            shared_formula_source = "snapshot_chain_live2_peg_minus_exclusive_sum"
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

        if is_to_remove:
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
            "mapped_vm_name": mapped_vm,
            "mapped_vg_name": mapped_vg,
            "mapped_entity_name": mapped_entity,
            "vg_resolution_method": vg_resolution_method,
        })
        container_tree[c_name][mapped_entity].append(node_data)

    # --- STEP 4: Aggregate Final JSON Payload ---
    container_nodes = []
    all_c_names = set(container_tree.keys()).union(container_shared_nodes.keys())

    for c_name in all_c_names:
        entities = container_tree.get(c_name, {})
        c_total_exclusive = 0
        container_vdisk_ids = set()
        
        shared_clone_blocks = container_shared_nodes.get(c_name, [])
        if shared_clone_blocks:
            entities["Shared Clones"] = shared_clone_blocks

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

