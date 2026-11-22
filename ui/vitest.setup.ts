import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
});

// jsdom doesn't implement <canvas>'s 2D context; PdfViewer needs a non-null context to
// run its page-render pipeline, and SignaturePad rescales it via setTransform. A bare stub
// with the methods we call is enough - we never inspect what's drawn.
if (typeof HTMLCanvasElement !== "undefined") {
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({ setTransform: vi.fn() })) as never;
}

// jsdom in this config doesn't back window.localStorage with a working Web Storage. The email-
// link sign-in flow stashes the address there between requesting and completing a link, so give
// tests a real in-memory Storage. afterEach clears it to keep tests isolated.
if (typeof window !== "undefined" && typeof window.localStorage?.setItem !== "function") {
  const store = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (k) => (store.has(k) ? store.get(k)! : null),
    key: (i) => Array.from(store.keys())[i] ?? null,
    removeItem: (k) => void store.delete(k),
    setItem: (k, v) => void store.set(k, String(v)),
  };
  Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
}

afterEach(() => {
  window.localStorage?.clear();
});

// jsdom lacks ResizeObserver; SignaturePad feature-detects it. Provide a controllable stub
// whose callback is invokable from tests to exercise the resize-clears-pad path.
if (typeof globalThis.ResizeObserver === "undefined") {
  class ResizeObserverStub {
    constructor(cb: ResizeObserverCallback) {
      (globalThis as unknown as { __resizeCallbacks: ResizeObserverCallback[] }).__resizeCallbacks ??=
        [];
      (globalThis as unknown as { __resizeCallbacks: ResizeObserverCallback[] }).__resizeCallbacks.push(
        cb,
      );
    }
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
}
