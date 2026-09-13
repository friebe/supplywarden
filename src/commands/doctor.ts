import { loadConfig, resolveConfigFile } from "../config.js";
import { detectPackageManager, hasLockfile } from "../graph/npm.js";
import { readMetadata, validateMetadataShape } from "../metadata/store.js";
import { npmVersion, pnpmVersion } from "../registry/verify.js";
import { nowIso } from "../util/time.js";
import type { CommandResult } from "../types.js";
import { emptyReport } from "../report/model.js";

function npmSupportsOverrides(version: string): boolean {
  const [maj, min] = version.split(".").map(Number);
  return (maj ?? 0) > 8 || ((maj ?? 0) === 8 && (min ?? 0) >= 3);
}

export function runDoctor(opts: { cwd: string }): CommandResult {
  const messages: string[] = [];
  const issues: string[] = [];
  const cwd = opts.cwd;
  const config = loadConfig(cwd);

  const pnpm = pnpmVersion();
  const npm = npmVersion();
  const pm = detectPackageManager(cwd);

  if (pnpm) {
    messages.push(`pnpm ${pnpm} OK`);
  }

  if (pm === "npm") {
    if (!npm) {
      if (!pnpm) issues.push("npm is not available on PATH");
      else messages.push("npm missing; pnpm can still run supplywarden against this lockfile");
    } else if (!npmSupportsOverrides(npm)) {
      if (pnpm) {
        messages.push(`npm ${npm} < 8.3 (overrides); using pnpm ${pnpm} instead`);
      } else {
        issues.push(`npm ${npm} does not support overrides (need >= 8.3.0)`);
      }
    } else {
      messages.push(`npm ${npm} OK`);
    }
  } else if (pm === "pnpm") {
    if (!pnpm) issues.push("pnpm is not available on PATH");
  } else if (pm === "unknown") {
    issues.push("No lockfile found (package-lock.json / pnpm-lock.yaml / yarn.lock)");
  }

  if (pm !== "unknown") messages.push(`package manager: ${pm}`);

  if (!hasLockfile(cwd)) {
    issues.push("Lockfile missing or unreadable");
  }

  messages.push(`audit minSeverity: ${config.audit.minSeverity}`);

  const configFile = resolveConfigFile(cwd);
  if (configFile.legacy) {
    messages.push(
      `${configFile.path}: legacy config — rename to .supplywardenrc.json`,
    );
  }

  try {
    const metadata = readMetadata(cwd, config);
    if (metadata.entries.length) {
      const schemaErrors = validateMetadataShape(metadata);
      if (schemaErrors.length) issues.push(...schemaErrors);
      else messages.push(`security-metadata.json: ${metadata.entries.length} entries`);
    } else {
      messages.push("security-metadata.json: none (run supplywarden init)");
    }
  } catch (err) {
    issues.push(`metadata invalid: ${(err as Error).message}`);
  }

  const ok = issues.length === 0;
  return {
    exitCode: ok ? 0 : 1,
    messages: [...messages, ...issues.map((i) => `ERROR: ${i}`)],
    report: {
      ...emptyReport(cwd, ok ? "doctor: OK" : "doctor: FAILED"),
      generatedAt: nowIso(),
      summary: { issues: issues.length, packageManager: pm },
    },
  };
}
