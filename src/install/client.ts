import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { detectPackageManager } from "../graph/npm.js";
import type { InstallClient } from "../types.js";

const execFileAsync = promisify(execFile);

export function createStaticInstall(ok = true, error?: string): InstallClient {
  return {
    async install() {
      return { ok, error };
    },
  };
}

export function createLiveInstall(): InstallClient {
  return {
    async install(cwd: string) {
      const pm = detectPackageManager(cwd);
      const cmd = pm === "pnpm" ? "pnpm" : pm === "yarn" ? "yarn" : "npm";
      const args = ["install"];
      try {
        await execFileAsync(cmd, args, {
          cwd,
          encoding: "utf8",
          maxBuffer: 20 * 1024 * 1024,
          timeout: 300_000,
        });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: (err as Error).message || `${cmd} install failed` };
      }
    },
  };
}
