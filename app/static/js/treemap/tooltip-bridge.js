/**
 * Phase 3: SoA / nodeRefs metadata → existing #floating-tooltip DOM.
 * Mirrors classic showFloatingTooltip branches (shared / snap-share / garbage / leaf).
 */

/**
 * @typedef {object} TooltipDeps
 * @property {(bytes: number) => string} formatBytes
 * @property {(info: object) => string} getDisplayNodeName
 * @property {(usecs: number|string|null|undefined) => string} [formatUsecsToLocalTime]
 * @property {() => void} [applyTooltipTextStyle]
 * @property {(node: object) => number} [getRealNodeSum]
 * @property {(node: object) => number} [getLogicalNodeSum]
 * @property {(node: object) => number} [getVdiskSizeSum]
 * @property {string} [tooltipId]
 */

const DEFAULT_TOOLTIP_ID = "floating-tooltip";

/**
 * @param {TooltipDeps} deps
 * @returns {HTMLElement|null}
 */
function getTooltipEl(deps) {
    const id = (deps && deps.tooltipId) || DEFAULT_TOOLTIP_ID;
    return typeof document !== "undefined" ? document.getElementById(id) : null;
}

/**
 * @param {object} node
 * @param {TooltipDeps} deps
 * @returns {number}
 */
function realSumOf(node, deps) {
    if (deps.getRealNodeSum) return Number(deps.getRealNodeSum(node)) || 0;
    const d = node && node.data;
    if (!d) return 0;
    if (d.real_bytes !== undefined) return Number(d.real_bytes) || 0;
    if (d.physical_size !== undefined) return Number(d.physical_size) || 0;
    if (d.formatted_size && d.real_bytes == null) return Number(d.value) || 0;
    return Number(node.value) || 0;
}

/**
 * @param {object} node
 * @param {TooltipDeps} deps
 * @returns {number}
 */
function logicalSumOf(node, deps) {
    if (deps.getLogicalNodeSum) return Number(deps.getLogicalNodeSum(node)) || 0;
    const d = node && node.data;
    if (!d) return 0;
    if (d.logical_bytes !== undefined && d.logical_bytes !== null) return Number(d.logical_bytes) || 0;
    return 0;
}

/**
 * @param {object} node
 * @param {TooltipDeps} deps
 * @returns {number}
 */
function vdiskSizeSumOf(node, deps) {
    if (deps.getVdiskSizeSum) return Number(deps.getVdiskSizeSum(node)) || 0;
    const d = node && node.data;
    if (!d) return 0;
    if (d.vdisk_size !== undefined && d.vdisk_size !== null) return Number(d.vdisk_size) || 0;
    return 0;
}

/**
 * Build tooltip innerHTML for a layout / nodeRef node (does not touch the DOM).
 *
 * @param {object} node d3-like node with .data
 * @param {TooltipDeps} deps
 * @returns {string}
 */
export function buildTooltipHtml(node, deps) {
    if (!node || !node.data || !deps || typeof deps.formatBytes !== "function") return "";
    const formatBytes = deps.formatBytes;
    const getDisplayNodeName = deps.getDisplayNodeName || ((info) => (info && info.name) || "");
    const formatTime =
        deps.formatUsecsToLocalTime ||
        (() => "n/a");

    const info = node.data;
    const realSum = realSumOf(node, deps);
    const logicalSum = logicalSumOf(node, deps);
    const vdiskSizeSum = vdiskSizeSumOf(node, deps);
    const creationTime = formatTime(info.vdisk_creation_time_usecs);
    const isVmGroup = info.name && String(info.name).startsWith("VM:");
    const isVgGroup = info.name && String(info.name).startsWith("VG:");

    let html = `<div class="font-bold text-sky-400 border-b border-slate-700 pb-1 mb-1 break-all">${getDisplayNodeName(info)}</div>`;

    if (info.is_other_aggregate || node.__syntheticOther) {
        html += `
            <div><span class="text-slate-400">Aggregated:</span> <span class="text-amber-300 font-bold">${info.other_count || 0} small items</span></div>
            <div><span class="text-slate-400">Combined size:</span> <span class="text-emerald-300 font-bold">${info.formatted_size || formatBytes(info.real_bytes || 0)}</span></div>
            <div class="text-[0.85em] text-slate-500 mt-1">Click to zoom into parent folder</div>
        `;
        return html;
    }

    if (info.is_partial_extents_block) {
        html += `
            <div><span class="text-slate-400">Container:</span> <span class="font-mono text-slate-200">${info.container_name || "n/a"}</span></div>
            <div><span class="text-slate-400">Partial Extents:</span> <span class="text-amber-300 font-bold">${info.formatted_size || formatBytes(info.real_bytes || 0)}</span></div>
            <div class="text-[0.85em] text-slate-500 mt-1">Source: curator_cli display_garbage_report</div>
        `;
    } else if (info.is_total_garbage_block) {
        html += `
            <div><span class="text-slate-400">Container:</span> <span class="font-mono text-slate-200">${info.container_name || "n/a"}</span></div>
            <div><span class="text-slate-400">Total Garbage w/o PEG:</span> <span class="text-amber-300 font-bold">${info.formatted_size || formatBytes(info.real_bytes || 0)}</span></div>
            <div class="text-[0.85em] text-slate-500 mt-1">Source: curator_cli display_garbage_report</div>
        `;
    } else if (info.is_chain_snap_share_block) {
        const terms = info.snap_share_formula_terms || {};
        html += `
            <div><span class="text-slate-400">Chain ID:</span> <span class="font-mono text-slate-200 text-[0.85em] break-all">${info.chain_id || info.name || "n/a"}</span></div>
            <div><span class="text-slate-400">Chain Snap Share:</span> <span class="text-amber-300 font-bold">${info.formatted_size || formatBytes(info.real_bytes || 0)}</span></div>
            <div class="mt-1 pt-1 border-t border-slate-700/50 space-y-0.5">
                <div><span class="text-slate-400">Logical Live:</span> <span class="text-sky-300 font-bold">${formatBytes(terms.logical_live || 0)}</span></div>
                <div><span class="text-slate-400">Logical Shared Clone:</span> <span class="text-emerald-300 font-bold">${formatBytes(terms.logical_shared_clone || 0)}</span></div>
                <div><span class="text-slate-400">Logical Exclusive:</span> <span class="text-slate-200 font-bold">${formatBytes(terms.logical_exclusive || 0)}</span></div>
                <div><span class="text-slate-400">VDisk Exclusive Sum:</span> <span class="text-slate-200 font-bold">${formatBytes(terms.exclusive_sum || 0)}</span></div>
            </div>
            <div class="mt-1 pt-1 border-t border-slate-700/50"><span class="text-slate-400">VDisks in Chain:</span> <span class="font-mono text-slate-200 font-bold">${info.vdisk_ids ? info.vdisk_ids.length : 0}</span></div>
        `;
    } else if (info.is_shared_clone_block) {
        html += `
            <div><span class="text-slate-400">Root Chain ID:</span> <span class="font-mono text-slate-200 text-[0.85em] break-all">${info.chain_id || "n/a"}</span></div>
            <div><span class="text-slate-400">Total Phys Overhead:</span> <span class="text-amber-300 font-bold">${info.formatted_size}</span></div>
            <div class="mt-1 pt-1 border-t border-slate-700/50 space-y-0.5">
                <div><span class="text-slate-400 text-[0.85em]">Total Phys PEG:</span> <span class="text-emerald-300 font-bold text-[0.85em]">${info.formatted_total_peg || info.formatted_max_peg || "0 KiB"}</span></div>
                <div><span class="text-slate-400 text-[0.85em]">Max Log Clone:</span> <span class="text-sky-300 font-bold text-[0.85em]">${info.formatted_logical_clone} <span class="text-slate-500 font-normal">(Est Phys: ${info.formatted_physical_clone || formatBytes(info.logical_clone_bytes ? info.logical_clone_bytes * 2 : 0)})</span></span></div>
            </div>
            <div class="mt-1 pt-1 border-t border-slate-700/50"><span class="text-slate-400">Member Chains:</span> <span class="font-mono text-slate-200 font-bold">${info.member_chain_ids ? info.member_chain_ids.length : 0}</span></div>
            <div><span class="text-slate-400">VDisks in Family:</span> <span class="font-mono text-slate-200 font-bold">${info.vdisk_ids ? info.vdisk_ids.length : 0}</span></div>
        `;
    } else if (isVmGroup || isVgGroup) {
        const leafRows = [];
        const gatherRows = (n) => {
            if (!n) return;
            const nd = n.data || {};
            if (nd.vdisk_id !== undefined && nd.vdisk_id !== null) {
                leafRows.push({
                    id: String(nd.vdisk_id),
                    provisionBytes: Number(nd.vdisk_size || 0),
                });
            }
            if (n.children && n.children.length) {
                n.children.forEach(gatherRows);
            }
        };
        gatherRows(node);
        if (!leafRows.length && node.leaves && typeof node.leaves === "function") {
            node.leaves().forEach((leaf) => {
                const ld = leaf.data || {};
                if (ld.vdisk_id === undefined || ld.vdisk_id === null) return;
                leafRows.push({
                    id: String(ld.vdisk_id),
                    provisionBytes: Number(ld.vdisk_size || 0),
                });
            });
        }
        leafRows.sort((a, b) => b.provisionBytes - a.provisionBytes);
        const totalProvisionBytes = leafRows.reduce((acc, row) => acc + row.provisionBytes, 0);
        html += `
            <div><span class="text-slate-400">Group Type:</span> <span class="text-slate-200 font-bold">${isVmGroup ? "Virtual Machine" : "Volume Group"}</span></div>
            <div><span class="text-slate-400">Member VDisks:</span> <span class="text-emerald-300 font-bold">${leafRows.length}</span></div>
            <div><span class="text-slate-400">Total Provisioned:</span> <span class="text-emerald-300 font-bold">${formatBytes(totalProvisionBytes)}</span></div>
            <div class="mt-1 pt-1 border-t border-slate-700/50 text-[0.85em] text-slate-300 max-h-48 overflow-y-auto pr-1">
                ${leafRows.length ? leafRows.map((row, idx) => `
                    <div class="flex justify-between items-center py-0.5">
                        <span>${idx + 1}. ${row.id}</span>
                        <span class="text-amber-300 font-mono">${formatBytes(row.provisionBytes)}</span>
                    </div>
                `).join("") : `<div class="text-slate-500 italic">No member VDisks</div>`}
            </div>
        `;
    } else {
        // Physical (exclusive) + provisioned — Phase 3 contract fields.
        html += `<div><span class="text-slate-400">Exclusive Usage:</span> <span class="${info.is_to_remove ? "text-rose-400 font-bold" : "text-amber-300 font-bold"}">${formatBytes(realSum)}</span></div>`;
        if (logicalSum > 0 || info.logical_bytes !== undefined) {
            html += `<div><span class="text-slate-400">Logical Exclusive:</span> <span class="text-sky-300 font-bold">${formatBytes(logicalSum)}</span></div>`;
        }
        if (vdiskSizeSum > 0 || info.vdisk_size !== undefined) {
            html += `<div><span class="text-slate-400">Provisioned Size:</span> <span class="text-emerald-300 font-bold">${formatBytes(vdiskSizeSum)}</span></div>`;
        }
    }

    if (
        info.vdisk_id ||
        (!info.children &&
            !info.is_shared_clone_block &&
            !info.is_chain_snap_share_block &&
            !info.is_partial_extents_block &&
            !info.is_total_garbage_block)
    ) {
        html += `
            <div class="text-[0.85em] text-slate-300 space-y-0.5 mt-1 border-t border-slate-800 pt-1">
                <div><span class="text-slate-400">VDisk ID:</span> ${info.vdisk_id || "n/a"}</div>
                <div><span class="text-slate-400">Chain ID:</span> ${info.chain_id || "n/a"}</div>
                <div><span class="text-slate-400">Parent VDisk ID:</span> ${info.parent_vdisk_id || "n/a"}</div>
                <div><span class="text-slate-400">VDisk Name:</span> ${info.vdisk_name || "n/a"}</div>
                <div><span class="text-slate-400">Mutability:</span> ${info.mutability_state != null && info.mutability_state !== "" ? info.mutability_state : "n/a"}</div>
                ${(info.inherited_usage_bytes !== undefined && info.inherited_usage_bytes !== null) ? `<div><span class="text-slate-400">Shared Storage:</span> ${formatBytes(Number(info.inherited_usage_bytes) || 0)}</div>` : ""}
                <div><span class="text-slate-400">Creation Time:</span> ${creationTime}</div>
            </div>
        `;

        if (info.chain_info && Array.isArray(info.chain_info) && info.chain_info.length > 0) {
            html += `<div class="text-[0.85em] text-amber-300 font-semibold mt-1 border-t border-slate-800 pt-0.5">Exists in ${info.chain_info.length} Snapshot Trees</div>`;
        }
    }

    if (info.is_to_remove) {
        html += `<div class="text-[0.85em] text-rose-300 font-semibold mt-0.5">Status: Pending Curator Deletion</div>`;
    }

    return html;
}

/**
 * Show / refresh #floating-tooltip from a nodeRef.
 *
 * @param {MouseEvent|{clientX:number,clientY:number}} event
 * @param {object} node
 * @param {TooltipDeps} deps
 */
export function showFloatingTooltip(event, node, deps) {
    const tooltip = getTooltipEl(deps);
    if (!tooltip || !node) return;
    const html = buildTooltipHtml(node, deps);
    if (!html) return;
    tooltip.innerHTML = html;
    if (typeof deps.applyTooltipTextStyle === "function") deps.applyTooltipTextStyle();
    tooltip.classList.remove("hidden");
    moveFloatingTooltip(event, deps);
}

/**
 * @param {MouseEvent|{clientX:number,clientY:number}} event
 * @param {TooltipDeps} [deps]
 */
export function moveFloatingTooltip(event, deps = {}) {
    const tooltip = getTooltipEl(deps);
    if (!tooltip || !event) return;
    const xOffset = 15;
    const yOffset = 15;
    let posX = event.clientX + xOffset;
    let posY = event.clientY + yOffset;
    const vw = typeof window !== "undefined" ? window.innerWidth : 1024;
    const vh = typeof window !== "undefined" ? window.innerHeight : 768;
    if (posX + 240 > vw) posX = event.clientX - 250;
    if (posY + 160 > vh) posY = event.clientY - 170;
    tooltip.style.left = `${posX}px`;
    tooltip.style.top = `${posY}px`;
}

/**
 * @param {TooltipDeps} [deps]
 */
export function hideFloatingTooltip(deps = {}) {
    const tooltip = getTooltipEl(deps);
    if (tooltip) tooltip.classList.add("hidden");
}

/**
 * Extract Phase-3 contract fields from a node (for tests / inspector sync helpers).
 * @param {object} node
 * @returns {object}
 */
export function readNodeTooltipFields(node) {
    const info = (node && node.data) || {};
    return {
        vdisk_id: info.vdisk_id != null ? info.vdisk_id : null,
        physical: info.real_bytes != null ? info.real_bytes : info.physical_size != null ? info.physical_size : null,
        provisioned: info.vdisk_size != null ? info.vdisk_size : null,
        mutability: info.mutability_state != null ? info.mutability_state : null,
        chain_id: info.chain_id != null ? info.chain_id : null,
        is_shared_clone_block: !!info.is_shared_clone_block,
        is_chain_snap_share_block: !!info.is_chain_snap_share_block,
        is_partial_extents_block: !!info.is_partial_extents_block,
        is_total_garbage_block: !!info.is_total_garbage_block,
        is_other_aggregate: !!(info.is_other_aggregate || (node && node.__syntheticOther)),
    };
}

export default {
    buildTooltipHtml,
    showFloatingTooltip,
    moveFloatingTooltip,
    hideFloatingTooltip,
    readNodeTooltipFields,
};
