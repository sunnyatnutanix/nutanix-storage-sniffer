/**
 * Phase 2 Pixi viewport: Application / canvas lifecycle, setRoot rebuild, resize.
 * Mounts into #treemap and exposes the canvas for existing pointer handlers.
 */

import { Application, Container } from "../../vendor/pixi.min.mjs";
import { BatchRenderer } from "./batch-renderer.js";

const BG = 0x0f172a;

/**
 * @typedef {"classic"|"worker"|"pixi"} TreemapRendererMode
 */

export class PixiViewport {
    constructor() {
        /** @type {Application|null} */
        this.app = null;
        /** @type {HTMLElement|null} */
        this.host = null;
        /** @type {BatchRenderer|null} */
        this.batch = null;
        /** @type {Container|null} */
        this.world = null;
        this.ready = false;
        this.width = 0;
        this.height = 0;
        /** Last root signature so chrome-only updates can skip setRoot. */
        this._rootKey = null;
        this._pointerBound = false;
    }

    /**
     * @param {HTMLElement} hostEl typically #treemap
     * @param {object} [opts]
     * @param {number} [opts.width]
     * @param {number} [opts.height]
     * @param {(ev: MouseEvent) => void} [opts.onMouseMove]
     * @param {(ev: MouseEvent) => void} [opts.onMouseOut]
     * @param {(ev: MouseEvent) => void} [opts.onClick]
     */
    async init(hostEl, opts = {}) {
        if (this.ready && this.app) {
            if (opts.width && opts.height) this.resize(opts.width, opts.height);
            return this;
        }
        if (!hostEl) throw new Error("PixiViewport.init requires a host element");

        this.host = hostEl;
        // Clear classic canvas if present.
        hostEl.innerHTML = "";

        const width = Math.max(1, opts.width || hostEl.clientWidth || 1);
        const height = Math.max(1, opts.height || hostEl.clientHeight || 1);
        const dpr = typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1;

        const app = new Application();
        await app.init({
            width,
            height,
            background: BG,
            backgroundAlpha: 1,
            antialias: false,
            resolution: dpr,
            autoDensity: true,
            preference: "webgl",
            // Prefer no default interaction plugin cost on the stage; we use DOM listeners.
            // eventMode still available if needed later.
        });

        const canvas = app.canvas;
        canvas.id = "treemap-canvas";
        canvas.style.position = "absolute";
        canvas.style.top = "0";
        canvas.style.left = "0";
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;

        hostEl.appendChild(canvas);

        const world = new Container();
        world.interactiveChildren = false;
        world.eventMode = "none";
        app.stage.addChild(world);
        app.stage.eventMode = "none";
        app.stage.interactiveChildren = false;

        this.app = app;
        this.world = world;
        this.batch = new BatchRenderer(world);
        this.width = width;
        this.height = height;
        this.ready = true;

        if (!this._pointerBound) {
            if (opts.onMouseMove) canvas.addEventListener("mousemove", opts.onMouseMove);
            if (opts.onMouseOut) canvas.addEventListener("mouseout", opts.onMouseOut);
            if (opts.onClick) canvas.addEventListener("click", opts.onClick);
            this._pointerBound = true;
        }

        return this;
    }

    /**
     * Full geometry rebuild from pruned visible nodes.
     *
     * @param {object[]} visibleNodes
     * @param {object} opts batch rebuild options + optional rootKey
     * @returns {{ spriteCount: number, labelCount: number, uploadMs: number }}
     */
    setRoot(visibleNodes, opts = {}) {
        if (!this.ready || !this.batch) {
            throw new Error("PixiViewport.setRoot called before init");
        }
        const t0 = performance.now();
        const stats = this.batch.rebuild(visibleNodes, opts);
        this._rootKey = opts.rootKey != null ? opts.rootKey : this._rootKey;
        const uploadMs = performance.now() - t0;
        if (this.app && this.app.renderer) {
            this.app.renderer.render(this.app.stage);
        }
        return { ...stats, uploadMs };
    }

    /**
     * Tint / alpha / stroke refresh without recreating sprites.
     * @param {object} opts passed to BatchRenderer.updateChrome
     */
    updateChrome(opts = {}) {
        if (!this.batch) return;
        this.batch.updateChrome(opts);
        if (this.app && this.app.renderer) {
            this.app.renderer.render(this.app.stage);
        }
    }

    /**
     * @param {object|null} node
     * @param {(node: object) => object} [getVisualState]
     */
    setHover(node, getVisualState) {
        if (!this.batch) return;
        this.batch.setHover(node, getVisualState);
        if (this.app && this.app.renderer) {
            this.app.renderer.render(this.app.stage);
        }
    }

    /**
     * @param {number} width
     * @param {number} height
     */
    resize(width, height) {
        if (!this.app) return;
        const w = Math.max(1, width || 1);
        const h = Math.max(1, height || 1);
        if (w === this.width && h === this.height) return;
        this.width = w;
        this.height = h;
        this.app.renderer.resize(w, h);
        const canvas = this.app.canvas;
        if (canvas) {
            canvas.style.width = `${w}px`;
            canvas.style.height = `${h}px`;
        }
    }

    /**
     * @returns {string|null}
     */
    get rootKey() {
        return this._rootKey;
    }

    /**
     * @returns {HTMLCanvasElement|null}
     */
    get canvas() {
        return this.app ? this.app.canvas : null;
    }

    /**
     * @returns {number}
     */
    get spriteCount() {
        return this.batch ? this.batch.spriteCount : 0;
    }

    destroy() {
        if (this.batch) {
            this.batch.destroy();
            this.batch = null;
        }
        if (this.app) {
            this.app.destroy(true, { children: true, texture: false });
            this.app = null;
        }
        this.world = null;
        this.ready = false;
        this._pointerBound = false;
        this._rootKey = null;
        if (this.host) {
            // Leave host empty; caller may remount classic canvas.
            this.host.innerHTML = "";
        }
        this.host = null;
    }
}

/** @type {PixiViewport|null} */
let singleton = null;

/**
 * Shared viewport instance for the page orchestrator.
 * @returns {PixiViewport}
 */
export function getPixiViewport() {
    if (!singleton) singleton = new PixiViewport();
    return singleton;
}

/**
 * @returns {Promise<PixiViewport>}
 */
export async function ensurePixiViewport(hostEl, opts = {}) {
    const vp = getPixiViewport();
    await vp.init(hostEl, opts);
    return vp;
}

export default PixiViewport;
