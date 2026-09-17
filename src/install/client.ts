import { resolvePackageManager } from "../graph/npm.js";
import type { InstallClient, PackageManager } from "../types.js";
import { execPm } from "../util/pm-exec.js";

export function createStaticInstall(ok = true, error?: string): InstallClient {
  return {
    async install() {
      return { ok, error };
    },
    async runCommand() {
      return { ok, error };
    },
  };
}

export function createLiveInstall(): InstallClient {
  return {
    async install(cwd: string) {
      const pm = resolvePackageManager(cwd);
      try {
        await execPm(pm, ["install"], {
          cwd,
          timeout: 300_000,
          stdio: process.stdin.isTTY ? "inherit" : "pipe",
        });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: (err as Error).message || `${pm} install failed` };
      }
    },
    async runCommand(cwd, file, args) {
      try {
        if (file === "npx") {
          await execPm("npm", ["exec", "--yes", "--", ...args], {
            cwd,
            timeout: 600_000,
            stdio: process.stdin.isTTY ? "inherit" : "pipe",
          });
          return { ok: true };
        }
        const pm = (file === "npm" || file === "pnpm" || file === "yarn" ? file : resolvePackageManager(cwd)) as PackageManager;
        await execPm(pm, args, {
          cwd,
          timeout: 300_000,
          stdio: process.stdin.isTTY ? "inherit" : "pipe",
        });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: (err as Error).message || `${file} ${args.join(" ")} failed` };
      }
    },
  };
}
