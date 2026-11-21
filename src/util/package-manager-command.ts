import type { PackageManager } from "../types.js";

/**
 * Resolves the executable name used by child_process. npm is distributed as
 * npm.cmd on Windows, while pnpm and yarn keep their regular command names.
 */
export function packageManagerCommand(pm: PackageManager | "unknown"): string {
  if (pm === "pnpm") return "pnpm";
  if (pm === "yarn") return "yarn";
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

/** Converts an ENOENT process error into an actionable package-manager error. */
export function packageManagerError(command: string, error: unknown): string {
  if ((error as NodeJS.ErrnoException).code === "ENOENT") {
    return `ERROR: ${command.replace(/\.cmd$/, "")} is not available on PATH`;
  }
  return (error as Error).message || `${command} command failed`;
}