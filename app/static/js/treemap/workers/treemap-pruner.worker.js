/**
 * Treemap LOD pruner (Phase 1).
 * Runs off the main thread: drops/aggregates sub-pixel and tiny tiles.
 *
 * Message in:
 *   { type: "prune", requestId, count, viewportArea, minWidth, minHeight, minAreaFraction,
 *     x0, y0, x1, y1, area, flags, parentIndex, realBytes  (typed arrays, transferable) }
 *
 * Message out:
 *   { type: "prune-result", requestId, visibleIndices: Uint32Array,
 *     others: { parentIndex, count, bytes, x0, y0, x1, y1, tint }[] }
 */

const FLAG_LEAF = 1 << 0;
const FLAG_FOLDER = 1 << 1;
const FLAG_OTHER = 1 << 2;

function isSmall(w, h, area, minW, minH, minArea) {
    return w < minW || h < minH || area < minArea;
}

self.onmessage = (event) => {
    const msg = event.data || {};
    if (msg.type !== "prune") return;

    const t0 = performance.now();
    const count = msg.count | 0;
    const viewportArea = Math.max(1, Number(msg.viewportArea) || 1);
    const minW = Number(msg.minWidth) || 4;
    const minH = Number(msg.minHeight) || 4;
    const minAreaFraction = Number(msg.minAreaFraction);
    const minArea =
        Number.isFinite(minAreaFraction) && minAreaFraction > 0
            ? viewportArea * minAreaFraction
            : viewportArea * 0.0005;

    const x0 = msg.x0;
    const y0 = msg.y0;
    const x1 = msg.x1;
    const y1 = msg.y1;
    const area = msg.area;
    const flags = msg.flags;
    const parentIndex = msg.parentIndex;
    const realBytes = msg.realBytes;
    const itemCount = msg.itemCount;

    /** @type {Uint8Array} */
    const pruned = new Uint8Array(count);

    // Pass 1: mark geometrically small nodes (skip root index 0 — always keep).
    for (let i = 1; i < count; i++) {
        const w = x1[i] - x0[i];
        const h = y1[i] - y0[i];
        const a = area[i] > 0 ? area[i] : Math.max(0, w) * Math.max(0, h);
        if (isSmall(w, h, a, minW, minH, minArea)) {
            pruned[i] = 1;
        }
    }

    // Pass 2: if a folder is pruned, prune all of its descendants via parent links.
    for (let i = 1; i < count; i++) {
        let p = parentIndex[i];
        while (p > 0) {
            if (pruned[p] && (flags[p] & FLAG_FOLDER)) {
                pruned[i] = 1;
                break;
            }
            p = parentIndex[p];
        }
    }

    // Pass 3: per-parent aggregation of pruned direct children → synthetic "Other".
    /** @type {Map<number, { count: number, bytes: number, x0: number, y0: number, x1: number, y1: number, tint: number }>} */
    const otherByParent = new Map();

    for (let i = 1; i < count; i++) {
        if (!pruned[i]) continue;
        const p = parentIndex[i];
        if (p < 0 || (p > 0 && pruned[p])) {
            // Parent also pruned — do not emit Other under a hidden parent.
            continue;
        }
        // Only aggregate direct children that are pruned; skip nodes whose parent is pruned.
        // Prefer aggregating leaves / folder roots that were pruned as units (not every descendant
        // under an already-pruned folder — those have pruned parents).
        let agg = otherByParent.get(p);
        if (!agg) {
            agg = {
                count: 0,
                bytes: 0,
                x0: x0[i],
                y0: y0[i],
                x1: x1[i],
                y1: y1[i],
                tint: 0x0369a1,
            };
            otherByParent.set(p, agg);
        }
        const items = itemCount && itemCount[i] > 0 ? itemCount[i] : 1;
        agg.count += items;
        const bytes = realBytes ? Number(realBytes[i]) || 0 : 0;
        // Count bytes for leaves; for pruned folders use their realBytes (exclusive aggregate).
        agg.bytes += bytes;
        agg.x0 = Math.min(agg.x0, x0[i]);
        agg.y0 = Math.min(agg.y0, y0[i]);
        agg.x1 = Math.max(agg.x1, x1[i]);
        agg.y1 = Math.max(agg.y1, y1[i]);
    }

    // Visible = non-pruned. Root always included.
    const visibleList = [];
    for (let i = 0; i < count; i++) {
        if (!pruned[i]) visibleList.push(i);
    }

    const others = [];
    for (const [parentIdx, agg] of otherByParent) {
        if (agg.count <= 0) continue;
        // Degenerate residual → skip empty geometry
        if (!(agg.x1 > agg.x0 && agg.y1 > agg.y0)) continue;
        others.push({
            parentIndex: parentIdx,
            count: agg.count,
            bytes: agg.bytes,
            x0: agg.x0,
            y0: agg.y0,
            x1: agg.x1,
            y1: agg.y1,
            tint: agg.tint,
            flags: FLAG_OTHER | FLAG_LEAF,
        });
    }

    const visibleIndices = Uint32Array.from(visibleList);
    const workerMs = performance.now() - t0;

    self.postMessage(
        {
            type: "prune-result",
            requestId: msg.requestId,
            visibleIndices,
            others,
            workerMs,
            prunedCount: count - visibleList.length,
            inputCount: count,
        },
        [visibleIndices.buffer]
    );
};
