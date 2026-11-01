/**
 * Layout bridge (Phase 1): pack D3 treemap nodes → SoA typed arrays,
 * post to the pruner worker, apply visibleIndices + synthetic "Other" nodes.
 */

import { FLAG, cssColorToUint, flagsForNode } from "./color-style.js";

export { FLAG, cssColorToUint, flagsForNode };

const DEFAULT_MIN_WIDTH = 4;
const DEFAULT_MIN_HEIGHT = 4;
const DEFAULT_MIN_AREA_FRACTION = 0.0005; // 0.05% of viewport

/** @type {Worker|null} */
let prunerWorker = null;
let requestSeq = 0;
/** @type {Map<number, { resolve: Function, reject: Function }>} */
const pending = new Map();

/**
 * @returns {Worker}
 */
function getPrunerWorker() {
    if (prunerWorker) return prunerWorker;
    const url = new URL("./workers/treemap-pruner.worker.js", import.meta.url);
    prunerWorker = new Worker(url);
    prunerWorker.onmessage = (event) => {
        const msg = event.data || {};
        if (msg.type !== "prune-result") return;
        const entry = pending.get(msg.requestId);
        if (!entry) return;
        pending.delete(msg.requestId);
        entry.resolve(msg);
    };
    prunerWorker.onerror = (err) => {
        for (const [, entry] of pending) {
            entry.reject(err);
        }
        pending.clear();
    };
    return prunerWorker;
}

/**
 * Resolve active treemap renderer mode.
 * Query wins over localStorage. Values: classic | worker | pixi
 * @returns {"classic"|"worker"|"pixi"}
 */
export function getTreemapRendererMode() {
    try {
        const params = new URLSearchParams(window.location.search);
        const q = (params.get("renderer") || "").toLowerCase();
        if (q === "pixi" || q === "webgl") return "pixi";
        if (q === "worker") return "worker";
        if (q === "classic" || q === "canvas" || q === "2d") return "classic";
        const stored = (localStorage.getItem("treemap_renderer") || "").toLowerCase();
        if (stored === "pixi" || stored === "webgl") return "pixi";
        if (stored === "worker") return "worker";
        return "classic";
    } catch (_) {
        return "classic";
    }
}

/**
 * Feature flag: worker SoA prune path (also true for pixi, which reuses prune).
 * @returns {boolean}
 */
export function isWorkerRendererEnabled() {
    const mode = getTreemapRendererMode();
    return mode === "worker" || mode === "pixi";
}

/**
 * Feature flag: ?renderer=pixi | localStorage treemap_renderer=pixi
 * @returns {boolean}
 */
export function isPixiRendererEnabled() {
    return getTreemapRendererMode() === "pixi";
}

/**
 * Pack laid-out d3 descendants into parallel typed arrays + nodeRefs.
 *
 * @param {object[]} descendants depth-sorted or any order (index = array position)
 * @param {object} opts
 * @param {(node: object, index: number) => string|number} opts.getTintCss  CSS color or uint
 * @param {(node: object) => number} [opts.getRealBytes]
 * @returns {import('./layout-bridge.js').PackedLayout}
 */
export function packLayout(descendants, opts = {}) {
    const n = descendants.length;
    const x0 = new Float32Array(n);
    const y0 = new Float32Array(n);
    const x1 = new Float32Array(n);
    const y1 = new Float32Array(n);
    const area = new Float32Array(n);
    const tint = new Uint32Array(n);
    const flags = new Uint32Array(n);
    const parentIndex = new Int32Array(n);
    const realBytes = new Float64Array(n);
    const itemCount = new Uint32Array(n);
    /** @type {object[]} */
    const nodeRefs = new Array(n);

    /** @type {Map<object, number>} */
    const indexByNode = new Map();
    for (let i = 0; i < n; i++) {
        indexByNode.set(descendants[i], i);
    }

    const getTintCss = opts.getTintCss || (() => "#0369a1");
    const getRealBytes =
        opts.getRealBytes ||
        ((node) => {
            const d = node && node.data;
            if (!d) return 0;
            if (d.real_bytes !== undefined) return Number(d.real_bytes) || 0;
            if (d.physical_size !== undefined) return Number(d.physical_size) || 0;
            if (d.aggregate_exclusive_bytes !== undefined) return Number(d.aggregate_exclusive_bytes) || 0;
            return Number(node.value) || 0;
        });

    for (let i = 0; i < n; i++) {
        const node = descendants[i];
        nodeRefs[i] = node;
        x0[i] = node.x0;
        y0[i] = node.y0;
        x1[i] = node.x1;
        y1[i] = node.y1;
        const w = Math.max(0, node.x1 - node.x0);
        const h = Math.max(0, node.y1 - node.y0);
        area[i] = w * h;

        const tintVal = getTintCss(node, i);
        tint[i] = typeof tintVal === "number" ? tintVal >>> 0 : cssColorToUint(tintVal);

        flags[i] = flagsForNode(node);
        const p = node.parent;
        parentIndex[i] = p && indexByNode.has(p) ? indexByNode.get(p) : -1;
        realBytes[i] = getRealBytes(node);

        if (node.children && node.children.length) {
            let leaves = 0;
            if (typeof node.leaves === "function") {
                try {
                    leaves = node.leaves().length;
                } catch (_) {
                    leaves = 1;
                }
            } else {
                leaves = 1;
            }
            itemCount[i] = Math.max(1, leaves);
        } else {
            itemCount[i] = 1;
        }
    }

    return { x0, y0, x1, y1, area, tint, flags, parentIndex, realBytes, itemCount, nodeRefs, count: n };
}

/**
 * @param {ReturnType<typeof packLayout>} packed
 * @param {object} viewport
 * @param {number} viewport.width
 * @param {number} viewport.height
 * @param {object} [options]
 * @returns {Promise<{ visibleIndices: Uint32Array, others: object[], workerMs: number, prunedCount: number, inputCount: number }>}
 */
export function pruneAsync(packed, viewport, options = {}) {
    const worker = getPrunerWorker();
    const requestId = ++requestSeq;
    const viewportArea = Math.max(1, (viewport.width || 1) * (viewport.height || 1));

    const x0 = packed.x0.slice();
    const y0 = packed.y0.slice();
    const x1 = packed.x1.slice();
    const y1 = packed.y1.slice();
    const area = packed.area.slice();
    const flags = packed.flags.slice();
    const parentIndex = packed.parentIndex.slice();
    const realBytes = packed.realBytes.slice();
    // Prefer item counts for folder aggregation when worker supports it — send as realBytes overlay? 
    // Worker uses realBytes for GiB; send itemCount separately by encoding into a copy of flags? 
    // Send itemCount as transferable Float64 by reusing: post itemCount as Uint32Array.
    const itemCount = packed.itemCount ? packed.itemCount.slice() : new Uint32Array(packed.count);

    return new Promise((resolve, reject) => {
        pending.set(requestId, { resolve, reject });
        worker.postMessage(
            {
                type: "prune",
                requestId,
                count: packed.count,
                viewportArea,
                minWidth: options.minWidth ?? DEFAULT_MIN_WIDTH,
                minHeight: options.minHeight ?? DEFAULT_MIN_HEIGHT,
                minAreaFraction: options.minAreaFraction ?? DEFAULT_MIN_AREA_FRACTION,
                x0,
                y0,
                x1,
                y1,
                area,
                flags,
                parentIndex,
                realBytes,
                itemCount,
            },
            [x0.buffer, y0.buffer, x1.buffer, y1.buffer, area.buffer, flags.buffer, parentIndex.buffer, realBytes.buffer, itemCount.buffer]
        );
    });
}

/**
 * Format bytes for the synthetic "Other" label (GiB-oriented, matches plan wording).
 * @param {number} bytes
 * @returns {string}
 */
export function formatGiBLabel(bytes) {
    const b = Number(bytes) || 0;
    if (b <= 0) return "0 GiB";
    const gib = b / (1024 * 1024 * 1024);
    if (gib >= 0.01) return `${gib.toFixed(2)} GiB`;
    const mib = b / (1024 * 1024);
    if (mib >= 0.01) return `${mib.toFixed(2)} MiB`;
    return `${(b / 1024).toFixed(2)} KiB`;
}

/**
 * Build synthetic d3-like nodes for worker "Other" aggregates and merge with visible refs.
 *
 * @param {ReturnType<typeof packLayout>} packed
 * @param {{ visibleIndices: Uint32Array|number[], others: object[] }} pruneResult
 * @param {object} [opts]
 * @param {(bytes: number) => string} [opts.formatBytes]
 * @returns {{ visibleNodes: object[], visibleIndices: number[], syntheticNodes: object[], spriteCount: number }}
 */
export function applyPruneResults(packed, pruneResult, opts = {}) {
    const formatBytes = opts.formatBytes || formatGiBLabel;
    const visibleIndices = Array.from(pruneResult.visibleIndices || []);
    const visibleNodes = visibleIndices.map((i) => packed.nodeRefs[i]).filter(Boolean);

    const syntheticNodes = [];
    const others = pruneResult.others || [];
    for (let o = 0; o < others.length; o++) {
        const rec = others[o];
        const parentRef = rec.parentIndex >= 0 ? packed.nodeRefs[rec.parentIndex] : null;
        const label = `Other small files: ${rec.count} items, ${formatBytes(rec.bytes)}`;
        const data = {
            name: label,
            value: Math.max(1, rec.bytes || 1),
            real_bytes: rec.bytes || 0,
            formatted_size: formatBytes(rec.bytes || 0),
            is_other_aggregate: true,
            other_count: rec.count,
            other_parent_name: parentRef && parentRef.data ? parentRef.data.name : null,
        };
        const synth = {
            data,
            depth: parentRef ? (parentRef.depth || 0) + 1 : 1,
            height: 0,
            parent: parentRef,
            children: null,
            value: data.value,
            x0: rec.x0,
            y0: rec.y0,
            x1: rec.x1,
            y1: rec.y1,
            isSearchMatch: false,
            isAncestorSearchMatch: false,
            isEffectiveSearchMatch: true,
            __syntheticOther: true,
            __parentIndex: rec.parentIndex,
        };
        syntheticNodes.push(synth);
        visibleNodes.push(synth);
    }

    // Keep paint order: shallow → deep (folders under children), then synthetics last among peers.
    visibleNodes.sort((a, b) => (a.depth || 0) - (b.depth || 0));

    return {
        visibleNodes,
        visibleIndices,
        syntheticNodes,
        spriteCount: visibleNodes.length,
        visibleCount: visibleNodes.length,
    };
}

/**
 * Yield to the browser so packing → prune handoff does not freeze >50ms chunks.
 * @returns {Promise<void>}
 */
export function yieldToMain() {
    return new Promise((resolve) => {
        if (typeof requestAnimationFrame === "function") {
            requestAnimationFrame(() => resolve());
        } else {
            setTimeout(resolve, 0);
        }
    });
}

/**
 * Full Phase-1 pipeline: pack → yield → prune → apply.
 *
 * @param {object[]} descendants
 * @param {{ width: number, height: number }} viewport
 * @param {object} opts pack + prune options; getTintCss required for correct colors
 * @returns {Promise<{ packed: object, pruneResult: object, applied: object, layoutMs: number, workerMs: number }>}
 */
export async function packAndPrune(descendants, viewport, opts = {}) {
    const tLayout0 = performance.now();
    const packed = packLayout(descendants, opts);
    const layoutMs = performance.now() - tLayout0;

    await yieldToMain();

    const pruneResult = await pruneAsync(packed, viewport, opts);
    const applied = applyPruneResults(packed, pruneResult, opts);

    return {
        packed,
        pruneResult,
        applied,
        layoutMs,
        workerMs: pruneResult.workerMs || 0,
    };
}

/**
 * Update window.__treemapPerf with Phase-1 timings.
 * @param {object} partial
 */
export function recordTreemapPerf(partial) {
    const prev = (typeof window !== "undefined" && window.__treemapPerf) || {};
    const next = {
        layoutMs: 0,
        workerMs: 0,
        uploadMs: 0,
        drawMs: 0,
        hitTestMs: 0,
        hitTestMethod: null,
        spriteCount: 0,
        visibleCount: 0,
        spatialCells: 0,
        lastRelayoutReason: null,
        ...prev,
        ...partial,
        updatedAt: Date.now(),
    };
    if (typeof window !== "undefined") {
        window.__treemapPerf = next;
    }
    return next;
}
