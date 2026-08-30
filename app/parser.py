import re

def parse_size_to_bytes(size_str: str) -> int:
    if not size_str or size_str.strip() in ["", "-", "n/a", "N/A"]:
        return 0
    s = size_str.strip().replace(",", "")
    match = re.search(r'([0-9.]+)\s*([A-Za-z]+)?', s)
    if not match:
        return 0
    val = float(match.group(1))
    unit = (match.group(2) or "bytes").upper()

    if unit in ["B", "BYTE", "BYTES"]:
        return int(val)
    elif unit in ["KIB", "KB", "K"]:
        return int(val * 1024)
    elif unit in ["MIB", "MB", "M"]:
        return int(val * 1024**2)
    elif unit in ["GIB", "GB", "G"]:
        return int(val * 1024**3)
    elif unit in ["TIB", "TB", "T"]:
        return int(val * 1024**4)
    elif unit in ["PIB", "PB", "P"]:
        return int(val * 1024**5)
    return int(val)

def parse_vdisk_configure_printer(log_text: str):
    vdisks = []
    blocks = re.split(r'(?:\r?\n|^)(?=vdisk_id\s*:)', log_text)
    
    # Define integer, boolean, string, and categorical keys to extract dynamically
    int_keys = [
        "vdisk_id", "vdisk_size", "parent_vdisk_id", "container_id", "snapshot_chain_id", 
        "originating_vdisk_id", "originating_cluster_id", "originating_cluster_incarnation_id", 
        "clone_source_vdisk_id", "data_log_id", "flush_log_id", "vdisk_creation_time_usecs", 
        "creation_time_usecs", "last_modification_time_usecs", "vdisk_snapshot_time_usecs",
        "originating_vdisk_snapshot_time_usecs", "time_to_live_usecs_hint"
        , "hint_total_reserved_capacity"
    ]
    bool_keys = [
        "to_remove", "shell_vdisk", "never_hosted", "has_complete_data", "is_metadata_vdisk", 
        "root_of_removable_subtree", "always_write_emap_extents", "avoid_vblock_copy_when_leaf", 
        "may_be_parent", "has_incomplete_ancestor", "snapshot_draining", "parent_draining", 
        "clone_parent_draining", "in_recycle_bin"
    ]
    str_keys = [
        "vdisk_name", "vdisk_uuid", "chain_id", "parent_chain_id", "lineage_id", "nfs_file_name", 
        "parent_nfs_file_name_hint", "closest_named_ancestor", "owner_id", "vdisk_snapshot_uuid"
    ]
    cat_keys = [
        "vdisk_type", "mutability_state", "oplog_type", "last_updated_pithos_version", 
        "iscsi_multipath_protocol"
    ]

    for b in blocks:
        if not b.strip():
            continue
            
        vd = {}
        
        # Extract Integers
        for key in int_keys:
            m = re.search(fr'^\s*{key}\s*:\s*(-?\d+)', b, re.MULTILINE)
            if m: vd[key] = int(m.group(1))

        # Extract Booleans
        for key in bool_keys:
            m = re.search(fr'^\s*{key}\s*:\s*(true|false)', b, re.MULTILINE | re.IGNORECASE)
            if m: vd[key] = m.group(1).lower() == 'true'

        # Extract Strings
        for key in str_keys:
            m = re.search(fr'^\s*{key}\s*:\s*"([^"]+)"', b, re.MULTILINE)
            if m: vd[key] = m.group(1)

        # Extract Categories
        for key in cat_keys:
            m = re.search(fr'^\s*{key}\s*:\s*(\w+)', b, re.MULTILINE)
            if m: vd[key] = m.group(1)

        # Extract List (vdisk_creator_loc)
        locs = re.findall(r'^\s*vdisk_creator_loc\s*:\s*(\d+)', b, re.MULTILINE)
        if locs:
            vd["vdisk_creator_loc"] = [int(l) for l in locs]

        # Extract Nested: params
        params_match = re.search(r'params\s*{([^}]+)}', b, re.MULTILINE)
        if params_match:
            p_text = params_match.group(1)
            vd["params"] = {}
            m = re.search(r'replica_placement_policy_id\s*:\s*(\d+)', p_text)
            if m: vd["params"]["replica_placement_policy_id"] = int(m.group(1))
            m = re.search(r'replica_placement_policy_uuid\s*:\s*"([^"]+)"', p_text)
            if m: vd["params"]["replica_placement_policy_uuid"] = m.group(1)
            m = re.search(r'num_shards\s*:\s*(\d+)', p_text)
            if m: vd["params"]["num_shards"] = int(m.group(1))
            m = re.search(r'total_reserved_capacity\s*:\s*(\d+)', p_text)
            if m: vd["params"]["total_reserved_capacity"] = int(m.group(1))

        # Extract Nested: vdisk_creation_context
        ctx_match = re.search(r'vdisk_creation_context\s*{([^}]+)}', b, re.MULTILINE)
        if ctx_match:
            c_text = ctx_match.group(1)
            vd["vdisk_creation_context"] = {}
            m = re.search(r'replication_mode\s*:\s*(\d+)', c_text)
            if m: vd["vdisk_creation_context"]["replication_mode"] = int(m.group(1))

        if "vdisk_id" in vd:
            vdisks.append(vd)
        
    return vdisks

def parse_snapshot_tree_printer(log_text: str) -> dict:
    """Parses snapshot_tree_printer output to map VDisk IDs to their chain lineages (handles 1-to-Many)."""
    vdisk_chain_map = {}
    chain_counter = 0

    for line in log_text.splitlines():
        line = line.strip()
        if line.startswith("["):
            entries = re.findall(r'\[(\d+)\(([^)]*)\)\]', line)
            if not entries:
                continue

            chain_counter += 1
            chain_ids = [e[0] for e in entries]

            for idx, (vd_id, args_str) in enumerate(entries):
                args_list = args_str.split(',')
                ct_val = "n/a"
                dt_val = "n/a"
                flags = []

                for arg in args_list:
                    arg = arg.strip()
                    if arg.startswith("ct="):
                        ct_val = arg[3:]
                    elif arg.startswith("dt="):
                        dt_val = arg[3:]
                    elif arg:
                        flags.append(arg)

                if vd_id not in vdisk_chain_map:
                    vdisk_chain_map[vd_id] = []

                vdisk_chain_map[vd_id].append({
                    "chain_index": chain_counter,
                    "chain_length": len(chain_ids),
                    "position": idx + 1,
                    "ct": ct_val,
                    "dt": dt_val,
                    "flags": ", ".join(flags) if flags else "none",
                    "chain_ids": chain_ids
                })

    return vdisk_chain_map

def parse_curator_usage(curator_log: str) -> dict:
    usage = {}
    for line in curator_log.splitlines():
        if "|" in line and not line.startswith("+"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2 and parts[0].isdigit():
                vd_id = parts[0]
                exclusive_str = parts[1]
                usage[vd_id] = parse_size_to_bytes(exclusive_str)
    return usage

def parse_curator_chain_usage(chain_log: str) -> dict:
    """Parses ===CURATOR_CHAIN_USAGE_START=== section mapping chain_id to comprehensive usage metrics."""
    chain_usage = {}
    for line in chain_log.splitlines():
        if "|" in line and not line.startswith("+"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 2:
                cid = parts[0]
                if cid.lower().startswith("chain"):
                    continue
                
                loc_excl = parse_size_to_bytes(parts[1]) if len(parts) > 1 else 0
                loc_excl_snap = parse_size_to_bytes(parts[2]) if len(parts) > 2 else 0
                loc_live = parse_size_to_bytes(parts[3]) if len(parts) > 3 else 0
                loc_dedup = parse_size_to_bytes(parts[4]) if len(parts) > 4 else 0
                loc_clone = parse_size_to_bytes(parts[5]) if len(parts) > 5 else 0
                phys_peg = parse_size_to_bytes(parts[6]) if len(parts) > 6 else 0

                primary_usage = max(loc_excl, loc_live)

                chain_usage[cid] = {
                    "logical_exclusive": loc_excl,
                    "logical_exclusive_snapshot": loc_excl_snap,
                    "logical_live": loc_live,
                    "logical_shared_dedup": loc_dedup,
                    "logical_shared_clone": loc_clone,
                    "physical_peg": phys_peg,
                    "primary_usage": primary_usage
                }
    return chain_usage

def parse_ncli_vms(ncli_vm_log: str) -> dict:
    def _extract_vm_vdisk_ids(vdisk_entry: str):
        ids = []
        if not vdisk_entry:
            return ids
        for token in [t.strip() for t in vdisk_entry.split(",") if t.strip()]:
            parts = token.split("::")
            if not parts:
                continue
            tail = parts[-1].strip()
            if tail.isdigit():
                ids.append(tail)
                continue
            # Pattern: NFS:2:0:270 -> vdisk id is final field
            nfs_parts = tail.split(":")
            if nfs_parts and nfs_parts[-1].strip().isdigit():
                ids.append(nfs_parts[-1].strip())
        return ids

    vms = {}
    blocks = ncli_vm_log.split("Id                        :")
    for b in blocks[1:]:
        vm_id_match = re.search(r'^\s*([^\n]+)', b)
        vm_uuid_match = re.search(r'Uuid\s*:\s*([^\n]+)', b)
        name_match = re.search(r'Name\s*:\s*([^\n]+)', b)
        vdisks_match = re.search(r'VDisks\s*:\s*([^\n]+)', b)

        if vm_uuid_match and name_match:
            vm_uuid = vm_uuid_match.group(1).strip()
            vm_name = name_match.group(1).strip()
            vdisks_raw = vdisks_match.group(1).strip() if vdisks_match else ""
            vdisk_list = [v.strip() for v in vdisks_raw.split(",") if v.strip()]
            vm_vdisk_ids = _extract_vm_vdisk_ids(vdisks_raw)

            vm_entry = {
                "uuid": vm_uuid,
                "name": vm_name,
                "vdisks": vdisk_list,
                "vdisk_ids": vm_vdisk_ids,
            }
            vms[vm_uuid] = vm_entry
            if vm_id_match:
                vms[vm_id_match.group(1).strip()] = vm_entry
    return vms

def parse_ncli_volume_groups(ncli_vg_log: str) -> dict:
    vgs = {}
    if not ncli_vg_log:
        return vgs

    # Split by blank-line separated records; this works when Name appears before UUID.
    blocks = re.split(r'\n\s*\n+', ncli_vg_log.strip(), flags=re.MULTILINE)
    for b in blocks:
        if not b.strip():
            continue

        uuid_match = re.search(r'^\s*UUID\s*:\s*([a-f0-9\-]+)\s*$', b, re.IGNORECASE | re.MULTILINE)
        name_match = re.search(r'^\s*Name\s*:\s*([^\n]+)$', b, re.IGNORECASE | re.MULTILINE)
        disks_match = re.search(r'^\s*Disks\s*:\s*\[(.*?)\]\s*$', b, re.DOTALL | re.IGNORECASE | re.MULTILINE)

        if not (uuid_match and name_match):
            continue

        vg_uuid = uuid_match.group(1).strip()
        vg_name = name_match.group(1).strip()
        disk_uuids = []
        disk_container_ids = []

        if disks_match:
            disks_str = disks_match.group(1).replace('\n', '').replace('\r', '')
            disk_uuids = re.findall(r'VM Disk UUID=([a-f0-9\-]+)', disks_str, re.IGNORECASE)
            disk_container_ids = re.findall(r'Container ID=(\d+)', disks_str, re.IGNORECASE)

        vgs[vg_uuid] = {
            "uuid": vg_uuid,
            "name": vg_name,
            "disk_uuids": disk_uuids,
            "disk_container_ids": disk_container_ids
        }
    return vgs

def parse_ncli_storage_pool(ncli_sp_log: str) -> dict:
    sp_info = {"name": "Default Storage Pool", "capacity_bytes": 0, "used_bytes": 0, "free_bytes": 0}
    name_match = re.search(r'Name\s*:\s*([^\n]+)', ncli_sp_log)
    cap_match = re.search(r'Capacity \(Physical\)\s*:\s*.*?\(([\d,]+)\s*bytes\)', ncli_sp_log)
    used_match = re.search(r'Used Space \(Physical\)\s*:\s*.*?\(([\d,]+)\s*bytes\)', ncli_sp_log)
    free_match = re.search(r'Free Space \(Physical\)\s*:\s*.*?\(([\d,]+)\s*bytes\)', ncli_sp_log)

    if name_match:
        sp_info["name"] = name_match.group(1).strip()
    if cap_match:
        sp_info["capacity_bytes"] = int(cap_match.group(1).replace(",", ""))
    if used_match:
        sp_info["used_bytes"] = int(used_match.group(1).replace(",", ""))
    if free_match:
        sp_info["free_bytes"] = int(free_match.group(1).replace(",", ""))

    return sp_info

def parse_ncli_containers(ncli_ctr_log: str) -> dict:
    containers = {}
    blocks = ncli_ctr_log.split("Id                        :")
    for b in blocks[1:]:
        id_match = re.search(r'^\s*.*::(\d+)', b) or re.search(r'^\s*(\d+)', b)
        name_match = re.search(r'Name\s*:\s*([^\n]+)', b)
        if id_match and name_match:
            cid = id_match.group(1).strip()
            cname = name_match.group(1).strip()
            containers[cid] = cname
    return containers


def parse_snapshot_tree_chain_ids(log_text: str) -> dict:
    """Parses snapshot_tree_printer --print_chain_ids mapping chains to all associated vdisks."""
    chain_to_vdisks = {}
    if not log_text:
        return chain_to_vdisks

    for line in log_text.splitlines():
        # Match format: [86fe7fa5-4515-42bd-a67c-a8ea1071820b][1][20404178]
        m = re.search(r'\[([a-f0-9\-]{36})\]\[(\d+)\]\[(.*?)\]', line, re.IGNORECASE)
        if m:
            cid = m.group(1)
            vdisks_str = m.group(3)
            # Split comma-separated IDs
            vdisk_ids = [int(v.strip()) for v in vdisks_str.split(',') if v.strip().isdigit()]
            chain_to_vdisks[cid] = vdisk_ids
    return chain_to_vdisks


def parse_ncli_containers_detailed(ncli_ctr_log: str) -> list:
    containers = []
    if not ncli_ctr_log:
        return containers

    blocks = ncli_ctr_log.split("Id                        :")
    for b in blocks[1:]:
        lines = b.splitlines()
        first_line = lines[0].strip() if lines else ""
        full_id = first_line
        short_id = full_id.split("::")[-1].strip() if full_id else ""

        def _extract(pattern: str):
            m = re.search(pattern, b, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        used_phys = _extract(r'Used Space \(Physical\)\s*:\s*([^\n]+)')
        free_phys = _extract(r'Free Space \(Physical\)\s*:\s*([^\n]+)')
        max_phys = _extract(r'Max Capacity \(Physical\)\s*:\s*([^\n]+)')
        explicit_res_logical = _extract(r'Explicit Res\. \(Logical\)\s*:\s*([^\n]+)')
        thick_logical = _extract(r'Thick Prov\. \(Logical\)\s*:\s*([^\n]+)')
        rf = _extract(r'Replication Factor\s*:\s*([^\n]+)')

        # Prefer explicit "(x bytes)" value where available.
        def _bytes_from_field(field_val: str):
            mb = re.search(r'\(([\d,]+)\s*bytes\)', field_val, re.IGNORECASE)
            if mb:
                return int(mb.group(1).replace(",", ""))
            return parse_size_to_bytes(field_val)

        c = {
            "id_full": full_id,
            "id_short": short_id,
            "uuid": _extract(r'Uuid\s*:\s*([^\n]+)'),
            "name": _extract(r'Name\s*:\s*([^\n]+)'),
            "storage_pool_id": _extract(r'Storage Pool Id\s*:\s*([^\n]+)'),
            "storage_pool_uuid": _extract(r'Storage Pool Uuid\s*:\s*([^\n]+)'),
            "free_space_physical": free_phys,
            "used_space_physical": used_phys,
            "max_capacity_physical": max_phys,
            "explicit_res_logical": explicit_res_logical,
            "thick_prov_logical": thick_logical,
            "replication_factor": rf,
            "free_space_physical_bytes": _bytes_from_field(free_phys),
            "used_space_physical_bytes": _bytes_from_field(used_phys),
            "max_capacity_physical_bytes": _bytes_from_field(max_phys),
            "explicit_res_logical_bytes": _bytes_from_field(explicit_res_logical),
            "thick_prov_logical_bytes": _bytes_from_field(thick_logical),
        }
        if c["name"]:
            containers.append(c)
    return containers


def parse_nfs_ls_sections(nfs_sections_log: str) -> dict:
    """
    Parse collector-emitted NFS section:
      ###CONTAINER:<name>
      <nfs_ls lines ...>
      ###CONTAINER_END###
    Returns {container_name: sorted([nfs_file_name...])}
    """
    result = {}
    if not nfs_sections_log:
        return result

    def _extract_candidate_name(line: str):
        t = (line or "").strip()
        if not t or t.startswith("[") or t.startswith("###"):
            return None
        if t.endswith(":"):
            return None

        parts = t.split()
        if not parts:
            return None

        # Handle symlink output: "name -> target"
        if len(parts) >= 3 and "->" in parts:
            arrow_idx = parts.index("->")
            if arrow_idx > 0:
                token = parts[arrow_idx - 1]
            else:
                token = parts[-1]
        else:
            token = parts[-1]

        token = token.rstrip("/")
        if not token:
            return None
        base = token.rsplit("/", 1)[-1].strip()
        if not base or base in (".", ".."):
            return None
        if base.lower() == "total":
            return None
        return base

    current_container = None
    for line in nfs_sections_log.splitlines():
        t = line.strip()
        if t.startswith("###CONTAINER:"):
            current_container = t.split("###CONTAINER:", 1)[1].strip()
            result.setdefault(current_container, set())
            continue
        if t.startswith("###CONTAINER_END###"):
            current_container = None
            continue
        if not current_container:
            continue

        candidate = _extract_candidate_name(t)
        if candidate:
            result[current_container].add(candidate)

    return {k: sorted(v) for k, v in result.items()}


def parse_nfs_ls_sections_detailed(nfs_sections_log: str) -> dict:
    """
    Returns:
      {
        container_name: [
          {
            "name": "<basename>",
            "raw_path": "<token as printed by nfs_ls>",
            "is_vgdisk_path": <bool>
          }, ...
        ]
      }
    """
    out = {}
    if not nfs_sections_log:
        return out

    def _extract_token(line: str):
        t = (line or "").strip()
        if not t or t.startswith("[") or t.startswith("###") or t.endswith(":"):
            return None
        parts = t.split()
        if not parts:
            return None
        if len(parts) >= 3 and "->" in parts:
            arrow_idx = parts.index("->")
            token = parts[arrow_idx - 1] if arrow_idx > 0 else parts[-1]
        else:
            token = parts[-1]
        token = token.rstrip("/")
        if not token:
            return None
        base = token.rsplit("/", 1)[-1].strip()
        if not base or base in (".", "..") or base.lower() == "total":
            return None
        return token, base

    current_container = None
    for line in nfs_sections_log.splitlines():
        t = line.strip()
        if t.startswith("###CONTAINER:"):
            current_container = t.split("###CONTAINER:", 1)[1].strip()
            out.setdefault(current_container, [])
            continue
        if t.startswith("###CONTAINER_END###"):
            current_container = None
            continue
        if not current_container:
            continue
        parsed = _extract_token(t)
        if not parsed:
            continue
        token, base = parsed
        out[current_container].append({
            "name": base,
            "raw_path": token,
            "is_vgdisk_path": ("/vgdisk/" in token or "vgdisk/" in token)
        })
    return out


def parse_vdisk_map_by_nfs(vdisks: list) -> dict:
    out = {}
    for vd in vdisks:
        nfs_name = vd.get("nfs_file_name")
        if nfs_name:
            out[nfs_name] = vd
    return out


