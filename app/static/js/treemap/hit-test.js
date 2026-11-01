/**
 * Phase 3: pointer → topmost visible buffer index via spatial hash.
 * Prefers the deepest leaf when multiple tiles cover the point.
 */

/**
 * @typedef {object} HitNode
 * @property {number} [x0]
 * @property {number} [y0]
 * @property {number} [x1]
 * @property {number} [y1]
 * @property {number} [depth]
 * @property {object} [data]
 * @property {object[]|null} [children]
 * @property {boolean} [__syntheticOther]
 */

/**
 * Score for "prefer deepest leaf": depth dominates; leaves / aggregates beat folders
 * at the same depth so a child tile wins over its parent when both contain the point.
 *
 * @param {HitNode} node
 * @returns {number}
 */
export function hitScore(node) {
    if (!node) return -1;
    const depth = Number(node.depth) || 0;
    const data = node.data || {};
    const isLeafLike =
        !!(data.vdisk_id != null) ||
        !!(data.is_other_aggregate) ||
        !!(node.__syntheticOther) ||
        !!(data.is_shared_clone_block) ||
        !!(data.is_shared_parent_vdisk) ||
        !!(data.is_chain_snap_share_block) ||
        !!(data.is_partial_extents_block) ||
        !!(data.is_total_garbage_block) ||
        !!(data.is_explicit_reserve_block) ||
        !(node.children && node.children.length);
    // depth * 2 + leaf bit → deepest leaf wins over shallower anything.
    return depth * 2 + (isLeafLike ? 1 : 0);
}

/**
 * Point-in-AABB using node geometry (or spatial-hash stored bounds).
 * @param {HitNode} node
 * @param {number} x
 * @param {number} y
 * @returns {boolean}
 */
export function pointInNode(node, x, y) {
    if (!node) return false;
    const x0 = Number(node.x0) || 0;
    const y0 = Number(node.y0) || 0;
    const x1 = Number(node.x1) || 0;
    const y1 = Number(node.y1) || 0;
    return x >= x0 && x <= x1 && y >= y0 && y <= y1;
}

/**
 * Hit-test via spatial hash → topmost buffer index.
 *
 * @param {number} x css px relative to canvas
 * @param {number} y css px relative to canvas
 * @param {import('./spatial-hash.js').SpatialHash|null} spatialHash
 * @param {HitNode[]} nodes visible nodes aligned with hash buffer indices
 * @param {object} [opts]
 * @param {boolean} [opts.fallbackLinear] if hash missing/empty, scan nodes reverse (classic)
 * @returns {{ index: number, node: HitNode|null, hitTestMs: number, method: "hash"|"linear"|"none" }}
 */
export function hitTest(x, y, spatialHash, nodes, opts = {}) {
    const t0 = typeof performance !== "undefined" ? performance.now() : 0;
    const list = nodes || [];
    const fallbackLinear = opts.fallbackLinear !== false;

    let bestIndex = -1;
    let bestNode = null;
    let bestScore = -1;
    let method = "none";

    if (spatialHash && spatialHash.cols > 0 && list.length) {
        method = "hash";
        const candidates = spatialHash.query(x, y);
        for (let i = 0; i < candidates.length; i++) {
            const idx = candidates[i];
            const node = list[idx];
            if (!node) continue;
            // Prefer hash bounds when present (avoids stale node geometry).
            const inside = spatialHash.bounds[idx]
                ? spatialHash.contains(idx, x, y)
                : pointInNode(node, x, y);
            if (!inside) continue;
            const score = hitScore(node);
            if (score > bestScore) {
                bestScore = score;
                bestIndex = idx;
                bestNode = node;
            }
        }
    } else if (fallbackLinear && list.length) {
        method = "linear";
        // Mirror classic reverse scan: depth-sorted ascending → reverse finds deepest first.
        for (let i = list.length - 1; i >= 0; i--) {
            const node = list[i];
            if (!pointInNode(node, x, y)) continue;
            bestIndex = i;
            bestNode = node;
            break;
        }
    }

    const hitTestMs = typeof performance !== "undefined" ? performance.now() - t0 : 0;
    return { index: bestIndex, node: bestNode, hitTestMs, method };
}

/**
 * Resolve pointer event against a canvas + spatial hash.
 *
 * @param {MouseEvent} event
 * @param {HTMLCanvasElement|HTMLElement} canvas
 * @param {import('./spatial-hash.js').SpatialHash|null} spatialHash
 * @param {HitNode[]} nodes
 * @param {object} [opts]
 * @returns {{ index: number, node: HitNode|null, hitTestMs: number, method: string, x: number, y: number }}
 */
export function hitTestEvent(event, canvas, spatialHash, nodes, opts = {}) {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const result = hitTest(x, y, spatialHash, nodes, opts);
    return { ...result, x, y };
}

export default { hitTest, hitTestEvent, hitScore, pointInNode };
