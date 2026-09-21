import { existsSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import type { SupplywardenConfig } from "./types.js";
import { DEFAULT_TIME_ZONE, parseDateLocale, parseTimeZone } from "./util/time.js";

export const CONFIG_FILENAME = ".supplywardenrc.json";
export const LEGACY_CONFIG_FILENAME = ".vulnfixrc.json";

export const DEFAULT_CONFIG: SupplywardenConfig = {
  upgradeRootThreshold: 3,
  autoApplyRootUpgrade: false,
  defaultReviewDays: 7,
  metadataPath: "security-metadata.json",
  impactWarnThreshold: 20,
  impactBlockThreshold: 100,
  audit: {
    minSeverity: "high",
  },
  dateLocale: "de",
  timeZone: DEFAULT_TIME_ZONE,
};

export type ResolvedConfigFile = {
  path: string | null;
  legacy: boolean;
};

export function resolveConfigFile(cwd: string): ResolvedConfigFile {
  const next = join(cwd, CONFIG_FILENAME);
  if (existsSync(next)) return { path: next, legacy: false };
  const legacy = join(cwd, LEGACY_CONFIG_FILENAME);
  if (existsSync(legacy)) return { path: legacy, legacy: true };
  return { path: null, legacy: false };
}

function defaults(): SupplywardenConfig {
  return { ...DEFAULT_CONFIG, audit: { ...DEFAULT_CONFIG.audit } };
}

export function loadConfig(cwd: string): SupplywardenConfig {
  const { path } = resolveConfigFile(cwd);
  if (!path) return defaults();
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<SupplywardenConfig>;
    return {
      upgradeRootThreshold: raw.upgradeRootThreshold ?? DEFAULT_CONFIG.upgradeRootThreshold,
      autoApplyRootUpgrade: raw.autoApplyRootUpgrade === true,
      defaultReviewDays: raw.defaultReviewDays ?? DEFAULT_CONFIG.defaultReviewDays,
      metadataPath: raw.metadataPath ?? DEFAULT_CONFIG.metadataPath,
      impactWarnThreshold: raw.impactWarnThreshold ?? DEFAULT_CONFIG.impactWarnThreshold,
      impactBlockThreshold: raw.impactBlockThreshold ?? DEFAULT_CONFIG.impactBlockThreshold,
      audit: {
        minSeverity: raw.audit?.minSeverity ?? DEFAULT_CONFIG.audit.minSeverity,
      },
      dateLocale: parseDateLocale(raw.dateLocale ?? DEFAULT_CONFIG.dateLocale),
      timeZone: parseTimeZone(raw.timeZone ?? DEFAULT_CONFIG.timeZone),
    };
  } catch {
    return defaults();
  }
}

function envActor(): string | undefined {
  for (const key of ["SUPPLYWARDEN_USER", "VULNFIX_USER", "USER", "USERNAME", "LOGNAME"] as const) {
    const value = process.env[key]?.trim();
    if (value) return value;
  }
  return undefined;
}

function osActor(): string | undefined {
  try {
    const name = userInfo().username?.trim();
    return name || undefined;
  } catch {
    return undefined;
  }
}

/** Who wrote the metadata row: env override, else the OS login of this CLI process. */
export function actorName(): string {
  return envActor() ?? osActor() ?? "unknown";
}
