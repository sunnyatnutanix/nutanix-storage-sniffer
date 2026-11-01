/**
 * Phase 2 batch renderer: Texture.WHITE + tinted sprites.
 * Selection / legend / search / hover update tint+alpha (and a stroke overlay)
 * without destroying the sprite pool when geometry is unchanged.
 */

import { Container, Graphics, Sprite, Text, Texture } from "../../vendor/pixi.min.mjs";

/** Minimum tile size (css px) before a label is considered. */
export const LABEL_MIN_WIDTH = 48;
export const LABEL_MIN_HEIGHT = 20;
/** Hard cap so dense maps stay sparse. */
export const MAX_LABELS = 64;

/**
 * @typedef {object} SpriteVisual
 * @property {number} tint 0xRRGGBB
 * @property {number} alpha 0..1
 * @property {"none"|"selected"|"highlight"|"filter"|"hover"} [stroke]
 * @property {number} [strokeColor]
 * @property {number} [strokeWidth]
 */

/**
 * @typedef {object} LabelSpec
 * @property {string} text
 * @property {number} x
 * @property {number} y
 * @property {number} [fontSize]
 * @property {string} [fill]
 * @property {string} [fontFamily]
 * @property {boolean} [bold]
 * @property {"left"|"center"} [align]
 */

export class BatchRenderer {
    /**
     * @param {Container} parent stage/world container
     */
    constructor(parent) {
        this.parent = parent;

        this.root = new Container();
        this.root.interactiveChildren = false;
        this.root.eventMode = "none";

        this.fillLayer = new Container();
        this.fillLayer.interactiveChildren = false;
        this.fillLayer.eventMode = "none";

        this.labelLayer = new Container();
        this.labelLayer.interactiveChildren = false;
        this.labelLayer.eventMode = "none";

        this.overlay = new Graphics();
        this.overlay.eventMode = "none";

        this.hoverOverlay = new Graphics();
        this.hoverOverlay.eventMode = "none";

        this.root.addChild(this.fillLayer, this.labelLayer, this.overlay, this.hoverOverlay);
        parent.addChild(this.root);

        /** @type {{ sprite: Sprite, node: object, baseTint: number, baseAlpha: number }[]} */
        this.entries = [];
        /** @type {WeakMap<object, number>} */
        this._indexByNode = new WeakMap();
        /** @type {Text[]} */
        this.labels = [];
        /** @type {object|null} */
        this.hoverNode = null;
        /** @type {((node: object) => SpriteVisual)|null} */
        this._getVisualState = null;

        this._white = Texture.WHITE;
    }

    /**
     * Destroy fill sprites + labels and rebuild from visible nodes.
     *
     * @param {object[]} visibleNodes nodes with x0,y0,x1,y1,data
     * @param {object} opts
     * @param {(node: object) => number} opts.getBaseTint 0xRRGGBB
     * @param {(node: object) => SpriteVisual} opts.getVisualState
     * @param {(node: object) => LabelSpec|null|undefined} [opts.getLabel]
     */
    rebuild(visibleNodes, opts = {}) {
        const getBaseTint = opts.getBaseTint || (() => 0x0369a1);
        const getVisualState = opts.getVisualState || (() => ({ tint: 0x0369a1, alpha: 1, stroke: "none" }));
        const getLabel = opts.getLabel || (() => null);

        this._clearFills();
        this._clearLabels();
        this.overlay.clear();
        this.hoverOverlay.clear();
        this.hoverNode = null;
        this._getVisualState = getVisualState;

        const nodes = visibleNodes || [];
        let labelCount = 0;

        for (let i = 0; i < nodes.length; i++) {
            const node = nodes[i];
            const w = Math.max(0, (node.x1 || 0) - (node.x0 || 0));
            const h = Math.max(0, (node.y1 || 0) - (node.y0 || 0));
            if (w <= 0 || h <= 0) continue;

            const baseTint = getBaseTint(node) >>> 0;
            const visual = getVisualState(node) || {};
            const tint = (visual.tint != null ? visual.tint : baseTint) >>> 0;
            const alpha = visual.alpha != null ? visual.alpha : 1;
            const sprite = new Sprite(this._white);
            sprite.x = node.x0 || 0;
            sprite.y = node.y0 || 0;
            sprite.width = w;
            sprite.height = h;
            sprite.tint = tint;
            sprite.alpha = alpha;
            sprite.eventMode = "none";
            this.fillLayer.addChild(sprite);
            const entryIndex = this.entries.length;
            this.entries.push({ sprite, node, baseTint, baseAlpha: alpha });
            this._indexByNode.set(node, entryIndex);

            if (labelCount < MAX_LABELS && w >= LABEL_MIN_WIDTH && h >= LABEL_MIN_HEIGHT) {
                const spec = getLabel(node);
                if (spec && spec.text) {
                    const label = this._makeLabel(spec);
                    this.labelLayer.addChild(label);
                    this.labels.push(label);
                    labelCount += 1;
                }
            }
        }

        this._paintOverlay(getVisualState);
        return {
            spriteCount: this.entries.length,
            labelCount: this.labels.length,
        };
    }

    /**
     * Update tint/alpha + overlay strokes without recreating sprites.
     * Geometry must still match `entries` (same visible set).
     *
     * @param {object} opts
     * @param {(node: object) => SpriteVisual} opts.getVisualState
     * @param {object|null} [opts.hoverNode]
     */
    updateChrome(opts = {}) {
        const getVisualState = opts.getVisualState || (() => ({ tint: 0x0369a1, alpha: 1 }));
        this._getVisualState = getVisualState;
        if (opts.hoverNode !== undefined) this.hoverNode = opts.hoverNode;

        for (let i = 0; i < this.entries.length; i++) {
            const entry = this.entries[i];
            const { sprite, node, baseTint } = entry;
            const visual = getVisualState(node) || {};
            const tint = (visual.tint != null ? visual.tint : baseTint) >>> 0;
            const alpha = visual.alpha != null ? visual.alpha : 1;
            entry.baseAlpha = alpha;
            // Hover brighten applied after chrome base.
            if (this.hoverNode && node === this.hoverNode) {
                sprite.tint = brightenTint(tint, 0.22);
                sprite.alpha = Math.min(1, alpha + 0.08);
            } else {
                sprite.tint = tint;
                sprite.alpha = alpha;
            }
        }

        this._paintOverlay(getVisualState);
        this._paintHoverStroke();
    }

    /**
     * Hover: tint only previous + next sprites; stroke on a dedicated overlay.
     * Does not rebuild the scene or re-walk all selection chrome.
     * @param {object|null} node
     * @param {(node: object) => SpriteVisual} [getVisualState]
     */
    setHover(node, getVisualState) {
        if (typeof getVisualState === "function") this._getVisualState = getVisualState;
        const resolve = this._getVisualState;

        const prev = this.hoverNode;
        const next = node || null;
        if (prev === next) {
            this._paintHoverStroke();
            return;
        }

        if (prev) {
            const prevEntry = this._entryFor(prev);
            if (prevEntry) {
                const visual = typeof resolve === "function" ? resolve(prev) || {} : {};
                const tint = (visual.tint != null ? visual.tint : prevEntry.baseTint) >>> 0;
                const alpha = visual.alpha != null ? visual.alpha : prevEntry.baseAlpha;
                prevEntry.sprite.tint = tint;
                prevEntry.sprite.alpha = alpha;
            }
        }

        this.hoverNode = next;

        if (next) {
            const nextEntry = this._entryFor(next);
            if (nextEntry) {
                const visual = typeof resolve === "function" ? resolve(next) || {} : {};
                const tint = (visual.tint != null ? visual.tint : nextEntry.baseTint) >>> 0;
                const alpha = visual.alpha != null ? visual.alpha : nextEntry.baseAlpha;
                nextEntry.sprite.tint = brightenTint(tint, 0.22);
                nextEntry.sprite.alpha = Math.min(1, alpha + 0.08);
            }
        }

        this._paintHoverStroke();
    }

    /**
     * @returns {number}
     */
    get spriteCount() {
        return this.entries.length;
    }

    destroy() {
        this._clearFills();
        this._clearLabels();
        this.overlay.clear();
        this.hoverOverlay.clear();
        if (this.root.parent) this.root.parent.removeChild(this.root);
        this.root.destroy({ children: true });
        this.entries = [];
        this._indexByNode = new WeakMap();
        this.labels = [];
        this.hoverNode = null;
        this._getVisualState = null;
    }

    /**
     * @param {object} node
     * @returns {{ sprite: Sprite, node: object, baseTint: number, baseAlpha: number }|null}
     */
    _entryFor(node) {
        if (!node) return null;
        const idx = this._indexByNode.get(node);
        if (idx == null) return null;
        return this.entries[idx] || null;
    }

    _clearFills() {
        for (let i = 0; i < this.entries.length; i++) {
            const { sprite } = this.entries[i];
            if (sprite.parent) sprite.parent.removeChild(sprite);
            sprite.destroy();
        }
        this.entries = [];
        this._indexByNode = new WeakMap();
        this.fillLayer.removeChildren();
    }

    _clearLabels() {
        for (let i = 0; i < this.labels.length; i++) {
            const label = this.labels[i];
            if (label.parent) label.parent.removeChild(label);
            label.destroy();
        }
        this.labels = [];
        this.labelLayer.removeChildren();
    }

    /**
     * @param {LabelSpec} spec
     * @returns {Text}
     */
    _makeLabel(spec) {
        const style = {
            fontFamily: spec.fontFamily || "sans-serif",
            fontSize: Math.max(8, Math.round(spec.fontSize || 11)),
            fill: spec.fill || "#ffffff",
            fontWeight: spec.bold === false ? "normal" : "bold",
            align: spec.align || "left",
            wordWrap: false,
        };
        const text = new Text({ text: String(spec.text), style });
        text.x = spec.x;
        text.y = spec.y;
        if (spec.align === "center") {
            text.anchor.set(0.5, 0.5);
        } else {
            text.anchor.set(0, 0);
        }
        text.eventMode = "none";
        return text;
    }

    /**
     * @param {(node: object) => SpriteVisual} getVisualState
     */
    _paintOverlay(getVisualState) {
        const g = this.overlay;
        g.clear();

        for (let i = 0; i < this.entries.length; i++) {
            const { node } = this.entries[i];
            const visual = getVisualState(node) || {};
            const stroke = visual.stroke || "none";
            if (stroke === "none" || stroke === "hover") continue;

            const w = Math.max(0, (node.x1 || 0) - (node.x0 || 0));
            const h = Math.max(0, (node.y1 || 0) - (node.y0 || 0));
            if (w <= 0 || h <= 0) continue;

            const color = visual.strokeColor != null ? visual.strokeColor : stroke === "selected" ? 0x22d3ee : 0xfbbf24;
            const width = visual.strokeWidth != null ? visual.strokeWidth : stroke === "selected" ? 2 : 1.5;
            g.rect((node.x0 || 0) + 0.5, (node.y0 || 0) + 0.5, Math.max(0, w - 1), Math.max(0, h - 1));
            g.stroke({ width, color, alpha: 1 });
        }
    }

    /**
     * White hover stroke on a dedicated layer (does not clear selection strokes).
     */
    _paintHoverStroke() {
        const g = this.hoverOverlay;
        g.clear();
        const node = this.hoverNode;
        if (!node) return;
        const w = Math.max(0, (node.x1 || 0) - (node.x0 || 0));
        const h = Math.max(0, (node.y1 || 0) - (node.y0 || 0));
        if (w <= 0 || h <= 0) return;
        g.rect((node.x0 || 0) + 0.5, (node.y0 || 0) + 0.5, Math.max(0, w - 1), Math.max(0, h - 1));
        g.stroke({ width: 1.5, color: 0xffffff, alpha: 1 });
    }
}

/**
 * Mix tint toward white for hover feedback without reallocating sprites.
 * @param {number} tint 0xRRGGBB
 * @param {number} amount 0..1
 * @returns {number}
 */
export function brightenTint(tint, amount = 0.2) {
    const a = Math.max(0, Math.min(1, amount));
    const r = (tint >>> 16) & 0xff;
    const g = (tint >>> 8) & 0xff;
    const b = tint & 0xff;
    const nr = Math.min(255, Math.round(r + (255 - r) * a));
    const ng = Math.min(255, Math.round(g + (255 - g) * a));
    const nb = Math.min(255, Math.round(b + (255 - b) * a));
    return ((nr << 16) | (ng << 8) | nb) >>> 0;
}

export default BatchRenderer;
