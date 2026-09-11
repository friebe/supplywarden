import { loadConfig } from "../config.js";
import { readMetadata } from "../metadata/store.js";
import { syncOverridesToPackageJson } from "../metadata/sync.js";
import { nowIso } from "../util/time.js";
import type { CommandResult } from "../types.js";
import { emptyReport } from "../report/model.js";

export function runSync(opts: { cwd: string }): CommandResult {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const metadata = readMetadata(cwd, config);
  const { overrides } = syncOverridesToPackageJson(cwd, metadata);
  return {
    exitCode: 0,
    messages: [`Synced ${Object.keys(overrides).length} override key(s) to package.json`],
    writtenFiles: ["package.json"],
    report: {
      ...emptyReport(cwd, "sync"),
      generatedAt: nowIso(),
      summary: { keys: Object.keys(overrides).length },
    },
  };
}
