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

        this.root.addChild(this.fillLayer, this.labelLayer, this.overlay);
        parent.addChild(this.root);

        /** @type {{ sprite: Sprite, node: object, baseTint: number }[]} */
        this.entries = [];
        /** @type {Text[]} */
        this.labels = [];
        /** @type {object|null} */
        this.hoverNode = null;

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

        const nodes = visibleNodes || [];
        let labelCount = 0;

        for (let i = 0; i < nodes.length; i++) {
            const node = nodes[i];
            const w = Math.max(0, (node.x1 || 0) - (node.x0 || 0));
            const h = Math.max(0, (node.y1 || 0) - (node.y0 || 0));
            if (w <= 0 || h <= 0) continue;

            const baseTint = getBaseTint(node) >>> 0;
            const visual = getVisualState(node) || {};
            const sprite = new Sprite(this._white);
            sprite.x = node.x0 || 0;
            sprite.y = node.y0 || 0;
            sprite.width = w;
            sprite.height = h;
            sprite.tint = (visual.tint != null ? visual.tint : baseTint) >>> 0;
            sprite.alpha = visual.alpha != null ? visual.alpha : 1;
            sprite.eventMode = "none";
            this.fillLayer.addChild(sprite);
            this.entries.push({ sprite, node, baseTint });

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
        if (opts.hoverNode !== undefined) this.hoverNode = opts.hoverNode;

        for (let i = 0; i < this.entries.length; i++) {
            const { sprite, node, baseTint } = this.entries[i];
            const visual = getVisualState(node) || {};
            sprite.tint = (visual.tint != null ? visual.tint : baseTint) >>> 0;
            sprite.alpha = visual.alpha != null ? visual.alpha : 1;
        }

        this._paintOverlay(getVisualState);
    }

    /**
     * Hover stroke only (fast path).
     * @param {object|null} node
     * @param {(node: object) => SpriteVisual} [getVisualState]
     */
    setHover(node, getVisualState) {
        this.hoverNode = node || null;
        if (typeof getVisualState === "function") {
            this._paintOverlay(getVisualState);
        } else {
            this._paintHoverOnly();
        }
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
        if (this.root.parent) this.root.parent.removeChild(this.root);
        this.root.destroy({ children: true });
        this.entries = [];
        this.labels = [];
        this.hoverNode = null;
    }

    _clearFills() {
        for (let i = 0; i < this.entries.length; i++) {
            const { sprite } = this.entries[i];
            if (sprite.parent) sprite.parent.removeChild(sprite);
            sprite.destroy();
        }
        this.entries = [];
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

        this._paintHoverOnly(false);
    }

    /**
     * @param {boolean} [clearFirst]
     */
    _paintHoverOnly(clearFirst = true) {
        const g = this.overlay;
        if (clearFirst) g.clear();
        const node = this.hoverNode;
        if (!node) return;
        const w = Math.max(0, (node.x1 || 0) - (node.x0 || 0));
        const h = Math.max(0, (node.y1 || 0) - (node.y0 || 0));
        if (w <= 0 || h <= 0) return;
        g.rect((node.x0 || 0) + 0.5, (node.y0 || 0) + 0.5, Math.max(0, w - 1), Math.max(0, h - 1));
        g.stroke({ width: 1.5, color: 0xffffff, alpha: 1 });
    }
}

export default BatchRenderer;
