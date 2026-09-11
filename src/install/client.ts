import { detectPackageManager } from "../graph/npm.js";
import type { InstallClient } from "../types.js";
import { execPm } from "../util/pm-exec.js";

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
      const detected = detectPackageManager(cwd);
      const pm = detected === "unknown" ? "npm" : detected;
      try {
        await execPm(pm, ["install"], {
          cwd,
          timeout: 300_000,
        });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: (err as Error).message || `${pm} install failed` };
      }
    },
  };
}
