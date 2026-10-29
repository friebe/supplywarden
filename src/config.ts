import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { SupplywardenConfig } from "./types.js";
export const CONFIG_FILENAME = ".supplywardenrc.json";

export const DEFAULT_CONFIG: SupplywardenConfig = {
  upgradeRootThreshold: 3,
  autoApplyRootUpgrade: false,
  htmlTemplate: "default",
  audit: {
    minSeverity: "high",
  },
};

function configPath(cwd: string): string | null {
  const path = join(cwd, CONFIG_FILENAME);
  return existsSync(path) ? path : null;
}

function defaults(): SupplywardenConfig {
  return { ...DEFAULT_CONFIG, audit: { ...DEFAULT_CONFIG.audit } };
}

export function loadConfig(cwd: string): SupplywardenConfig {
  const path = configPath(cwd);
  if (!path) return defaults();
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<SupplywardenConfig>;
    return {
      upgradeRootThreshold: raw.upgradeRootThreshold ?? DEFAULT_CONFIG.upgradeRootThreshold,
      autoApplyRootUpgrade: raw.autoApplyRootUpgrade === true,
      htmlTemplate: raw.htmlTemplate?.trim() || DEFAULT_CONFIG.htmlTemplate,
      audit: {
        minSeverity: raw.audit?.minSeverity ?? DEFAULT_CONFIG.audit.minSeverity,
      },
    };
  } catch {
    return defaults();
  }
}
