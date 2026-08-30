from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class VdiskNode:
    vdisk_id: str
    chain_id: str
    container_id: str
    parent_vdisk_id: Optional[str] = None
    parent_chain_id: Optional[str] = None
    children_vdisk_ids: List[str] = field(default_factory=list)
    exclusive_bytes: int = 0
    entity_type: str = "vdisk"
    entity_name: str = "VDisks"
    vm_name: Optional[str] = None
    vg_name: Optional[str] = None
    is_snapshot: bool = False
    is_to_remove: bool = False
    is_in_recycle_bin: bool = False


@dataclass
class ChainNode:
    chain_id: str
    vdisk_ids: List[str] = field(default_factory=list)
    parent_chain_ids: Set[str] = field(default_factory=set)
    child_chain_ids: Set[str] = field(default_factory=set)
    logical_live: int = 0
    logical_shared_clone: int = 0
    logical_exclusive_snapshot: int = 0
    physical_peg: int = 0
    shared_bytes: int = 0
    shared_formula_source: str = "missing_chain_id"
    shared_formula_terms: Dict[str, int] = field(default_factory=dict)


@dataclass
class ChainTree:
    chain_tree_id: str
    root_chain_id: str
    member_chain_ids: List[str] = field(default_factory=list)
    leaf_chain_ids: List[str] = field(default_factory=list)
    selected_shared_chain_id: Optional[str] = None
    selected_shared_bytes: int = 0
    leaf_candidates: List[Dict[str, int]] = field(default_factory=list)


@dataclass
class ContainerGraph:
    container_id: str
    container_name: str
    replication_factor: int
    vdisk_ids: List[str] = field(default_factory=list)
    entity_groups: Dict[str, List[str]] = field(default_factory=dict)
    chain_trees: List[ChainTree] = field(default_factory=list)
