/**
 * Phase 3: uniform grid spatial hash over visible tile AABBs.
 * Rebuild on layout / resize / root change; query returns candidate buffer indices.
 */

/** Default cell size in CSS pixels (plan: ~32–64). */
export const DEFAULT_CELL_SIZE = 48;

/**
 * @typedef {object} SpatialBounds
 * @property {number} x0
 * @property {number} y0
 * @property {number} x1
 * @property {number} y1
 */

export class SpatialHash {
    /**
     * @param {object} [opts]
     * @param {number} [opts.cellSize]
     */
    constructor(opts = {}) {
        this.cellSize = Math.max(8, opts.cellSize || DEFAULT_CELL_SIZE);
        this.width = 0;
        this.height = 0;
        this.cols = 0;
        this.rows = 0;
        /** @type {number[][]} cell → buffer indices that overlap the cell */
        this.cells = [];
        /** @type {SpatialBounds[]} parallel to insertion order (buffer index) */
        this.bounds = [];
        /** Generation counter bumped on each rebuild (for cache invalidation). */
        this.generation = 0;
        this.count = 0;
    }

    /**
     * Rebuild the grid from visible nodes (or plain AABB objects).
     *
     * @param {SpatialBounds[]} nodes nodes with x0,y0,x1,y1
     * @param {number} width viewport width (css px)
     * @param {number} height viewport height (css px)
     * @returns {{ count: number, cells: number, cellSize: number }}
     */
    rebuild(nodes, width, height) {
        const w = Math.max(1, width || 1);
        const h = Math.max(1, height || 1);
        const cell = this.cellSize;
        const cols = Math.max(1, Math.ceil(w / cell));
        const rows = Math.max(1, Math.ceil(h / cell));

        this.width = w;
        this.height = h;
        this.cols = cols;
        this.rows = rows;
        this.cells = new Array(cols * rows);
        for (let i = 0; i < this.cells.length; i++) this.cells[i] = [];
        this.bounds = [];
        this.count = 0;
        this.generation += 1;

        const list = nodes || [];
        for (let i = 0; i < list.length; i++) {
            const n = list[i];
            if (!n) continue;
            const x0 = Number(n.x0) || 0;
            const y0 = Number(n.y0) || 0;
            const x1 = Number(n.x1) || 0;
            const y1 = Number(n.y1) || 0;
            if (x1 <= x0 || y1 <= y0) continue;

            this.bounds[i] = { x0, y0, x1, y1 };
            this.count += 1;

            const c0 = clamp(Math.floor(x0 / cell), 0, cols - 1);
            const c1 = clamp(Math.floor((x1 - 1e-6) / cell), 0, cols - 1);
            const r0 = clamp(Math.floor(y0 / cell), 0, rows - 1);
            const r1 = clamp(Math.floor((y1 - 1e-6) / cell), 0, rows - 1);

            for (let r = r0; r <= r1; r++) {
                for (let c = c0; c <= c1; c++) {
                    this.cells[r * cols + c].push(i);
                }
            }
        }

        // Keep bounds length aligned with input index space even if some were skipped.
        if (this.bounds.length < list.length) this.bounds.length = list.length;

        return { count: this.count, cells: cols * rows, cellSize: cell };
    }

    /**
     * Candidate buffer indices whose cells cover (x, y). May include false positives
     * (AABB not containing the point); caller must refine.
     *
     * @param {number} x
     * @param {number} y
     * @returns {number[]}
     */
    query(x, y) {
        if (!this.cols || !this.rows || !this.cells.length) return [];
        if (x < 0 || y < 0 || x > this.width || y > this.height) {
            // Still allow slight overflow near edges of a resized canvas.
            if (x < -2 || y < -2 || x > this.width + 2 || y > this.height + 2) return [];
        }
        const c = clamp(Math.floor(x / this.cellSize), 0, this.cols - 1);
        const r = clamp(Math.floor(y / this.cellSize), 0, this.rows - 1);
        return this.cells[r * this.cols + c] || [];
    }

    /**
     * Exact AABB containment check against stored bounds for an index.
     * @param {number} index
     * @param {number} x
     * @param {number} y
     * @returns {boolean}
     */
    contains(index, x, y) {
        const b = this.bounds[index];
        if (!b) return false;
        return x >= b.x0 && x <= b.x1 && y >= b.y0 && y <= b.y1;
    }

    clear() {
        this.cells = [];
        this.bounds = [];
        this.cols = 0;
        this.rows = 0;
        this.width = 0;
        this.height = 0;
        this.count = 0;
        this.generation += 1;
    }
}

/**
 * @param {number} v
 * @param {number} lo
 * @param {number} hi
 */
function clamp(v, lo, hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

/**
 * Convenience singleton for page orchestrator (optional).
 * @type {SpatialHash|null}
 */
let singleton = null;

/** @returns {SpatialHash} */
export function getSpatialHash() {
    if (!singleton) singleton = new SpatialHash();
    return singleton;
}

export default SpatialHash;
