/**
 * The desktop app (Electron) exposes `window.desktop` through its preload
 * script: a network probe for the checks a browser cannot make, and saving the
 * client report straight to a PDF file. On the website it does not exist.
 */
import type { WebProbe } from "./core/web";

export interface DesktopApi extends WebProbe {
  version: string;
  platform: string;
  savePdf(fileName: string): Promise<{ saved: boolean; path?: string }>;
}

export const desktop: DesktopApi | undefined = (globalThis as { desktop?: DesktopApi }).desktop;
