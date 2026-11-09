import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "node:path";
import { NATIVE_SCHEME } from "@secure-app/shared/bridge";

/**
 * The SPA as a standalone bundle for the Mac app. `npm run build:web` writes
 * it where the Xcode project copies it from; it is gitignored and rebuilt,
 * never edited.
 *
 * - Relative asset paths and hash routes: the shell serves these files from
 *   its own scheme, and nothing may assume a host or a server-side fallback.
 * - No analytics and nothing remote: the page has no network of its own.
 * - A strict CSP in a meta tag, since the shell serves files, not headers.
 */

/** Where the Xcode project copies the bundle from. SECURE_APP_WEB_OUT moves it, for a trial build. */
export const WEB_OUT_DIR = process.env.SECURE_APP_WEB_OUT
  ? path.resolve(process.env.SECURE_APP_WEB_OUT)
  : path.resolve(import.meta.dirname, "../app/Resources/WebApp");

/** The bundle itself and the shell's signed direct loads. Nothing remote can run, connect or frame. */
export const WEB_CSP = [
  `default-src 'self' ${NATIVE_SCHEME}:`,
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "font-src 'self'",
  `img-src 'self' ${NATIVE_SCHEME}: data: blob:`,
  `frame-src 'self' ${NATIVE_SCHEME}:`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

const csp: Plugin = {
  name: "secure-app-csp",
  transformIndexHtml: (html) => html.replace("__WEB_CSP__", WEB_CSP),
};

export default defineConfig({
  root: import.meta.dirname,
  base: "./",
  build: {
    outDir: WEB_OUT_DIR,
    emptyOutDir: true,
    // Fonts and images stay files: a data: URI would need data: in font-src.
    assetsInlineLimit: 0,
  },
  plugins: [react(), csp],
});
