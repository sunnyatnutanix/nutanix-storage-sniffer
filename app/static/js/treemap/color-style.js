/**
 * Treemap color / flag helpers for SoA packing (Phase 1).
 * Ports CSS theme colors to uint32 RGB tints used by the worker bridge and
 * (later) Pixi batch sprites.
 */

/** @typedef {Record<string, string>} ThemeColors */

export const FLAG = Object.freeze({
    LEAF: 1 << 0,
    FOLDER: 1 << 1,
    OTHER: 1 << 2,
    SEARCH_MATCH: 1 << 3,
    SEARCH_EFFECTIVE: 1 << 4,
    HAS_CHILDREN: 1 << 5,
});

/**
 * Parse #rgb / #rrggbb / rgb()/rgba() into 0xRRGGBB (alpha ignored).
 * @param {string} css
 * @returns {number}
 */
export function cssColorToUint(css) {
    if (!css || typeof css !== "string") return 0x0369a1;
    const s = css.trim();
    if (s.startsWith("#")) {
        let hex = s.slice(1);
        if (hex.length === 3) {
            hex = hex.split("").map((c) => c + c).join("");
        }
        if (hex.length >= 6) {
            const n = Number.parseInt(hex.slice(0, 6), 16);
            return Number.isFinite(n) ? n : 0x0369a1;
        }
    }
    const m = s.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
    if (m) {
        return ((Number(m[1]) & 255) << 16) | ((Number(m[2]) & 255) << 8) | (Number(m[3]) & 255);
    }
    return 0x0369a1;
}

/**
 * @param {number} tint 0xRRGGBB
 * @returns {string} #rrggbb
 */
export function uintToCssHex(tint) {
    const n = (tint >>> 0) & 0xffffff;
    return `#${n.toString(16).padStart(6, "0")}`;
}

/**
 * Legend / entity category for a node data object (no active-chain highlight).
 * Mirrors getMappedEntityCategory + structural checks used by getEntityColor
 * when chain highlight context is not available.
 * @param {object} data
 * @returns {string|null}
 */
export function getMappedEntityCategory(data) {
    if (!data) return null;
    if (data.is_partial_extents_block) return "partialExtents";
    if (data.is_total_garbage_block) return "totalGarbage";
    if (data.is_chain_snap_share_block) return "chainSnapShare";
    if (data.is_shared_parent_vdisk || data.is_shared_clone_block) return "sharedClone";
    const mapped = String(data.mapped_entity_name || data.name || "");
    if (mapped.startsWith("VM:")) return "vm";
    if (mapped.startsWith("VG:")) return "vg";
    if (mapped === "Snapshots") return "snapshots";
    if (mapped === "Chain Snap Share") return "chainSnapShare";
    if (mapped === "Partial Extents") return "partialExtents";
    if (mapped === "Total Garbage w/o PEG") return "totalGarbage";
    if (mapped === "Shared Storage" || mapped.startsWith("Root VDisk-Chain-") || mapped.startsWith("Lineage ")) {
        return "sharedClone";
    }
    if (mapped === "Reserved Available Space") return "explicitReserve";
    if (mapped === "Recycle Bin") return "recycleBin";
    if (mapped.includes("Pending Deletion") || mapped.includes("to_remove")) return "pendingDeletion";
    if (mapped === "VDisks") return "otherVDisks";
    return null;
}

/**
 * Resolve a CSS color for node data using a theme map.
 * Callers that need active-chain / lineage overrides should pass a precomputed
 * css color (e.g. from page getEntityColor) via packLayout's getTintCss.
 * @param {object} data
 * @param {ThemeColors} themeColors
 * @returns {string}
 */
export function resolveEntityCssColor(data, themeColors) {
    const colors = themeColors || {};
    const fallback = colors.otherVDisks || "#0369a1";
    if (!data) return fallback;
    if (data.is_shared_parent_vdisk || data.name === "Shared Storage") return colors.sharedClone || fallback;
    if (data.is_chain_snap_share_block || data.name === "Chain Snap Share") return colors.chainSnapShare || fallback;
    if (data.is_partial_extents_block || data.name === "Partial Extents") return colors.partialExtents || fallback;
    if (data.is_total_garbage_block || data.name === "Total Garbage w/o PEG") return colors.totalGarbage || fallback;
    if (data.is_explicit_reserve_block || data.name === "Reserved Available Space") return colors.explicitReserve || fallback;
    if (data.is_thick_prov_vdisk || data.is_thick_prov_block || data.name === "Thick Provisioned") {
        return colors.thickProv || fallback;
    }
    if (data.is_shared_clone_block) return colors.sharedClone || fallback;
    if (data.is_free) return colors.freeSpace || fallback;
    if (data.is_in_recycle_bin || (data.name && data.name === "Recycle Bin")) return colors.recycleBin || fallback;
    if (
        data.is_to_remove ||
        (data.name && data.name.includes("to_remove")) ||
        (data.name && data.name.includes("Pending Deletion"))
    ) {
        return colors.pendingDeletion || fallback;
    }
    if (data.name && data.name.startsWith("VM:")) return colors.vm || fallback;
    if (data.name && data.name.startsWith("VG:")) return colors.vg || fallback;
    if (data.name && data.name.includes("Other VDisks")) return colors.otherVDisks || fallback;
    if (data.name && data.name === "Snapshots") return colors.snapshots || fallback;
    if (data.name && data.name.startsWith("Container-")) return colors.container || fallback;
    const mapped = getMappedEntityCategory(data);
    if (mapped && colors[mapped]) return colors[mapped];
    return fallback;
}

/**
 * @param {object} data
 * @param {ThemeColors} themeColors
 * @returns {number} 0xRRGGBB
 */
export function resolveEntityTint(data, themeColors) {
    return cssColorToUint(resolveEntityCssColor(data, themeColors));
}

/**
 * Build layout flags from a d3 hierarchy node.
 * @param {object} d3Node
 * @returns {number}
 */
export function flagsForNode(d3Node) {
    let f = 0;
    const hasChildren = !!(d3Node && d3Node.children && d3Node.children.length);
    if (hasChildren) {
        f |= FLAG.FOLDER | FLAG.HAS_CHILDREN;
    } else {
        f |= FLAG.LEAF;
    }
    if (d3Node && d3Node.isSearchMatch) f |= FLAG.SEARCH_MATCH;
    if (d3Node && d3Node.isEffectiveSearchMatch) f |= FLAG.SEARCH_EFFECTIVE;
    return f;
}
