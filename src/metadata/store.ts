import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { MetadataEntry, SecurityMetadata, SupplywardenConfig } from "../types.js";

export function metadataPath(cwd: string, config: SupplywardenConfig): string {
  return join(cwd, config.metadataPath);
}

export function emptyMetadata(): SecurityMetadata {
  return {
    $schema: "https://unpkg.com/supplywarden@latest/schema/security-metadata.schema.json",
    version: 1,
    entries: [],
  };
}

export function readMetadata(cwd: string, config: SupplywardenConfig): SecurityMetadata {
  const path = metadataPath(cwd, config);
  if (!existsSync(path)) return emptyMetadata();
  const parsed = JSON.parse(readFileSync(path, "utf8")) as SecurityMetadata;
  if (!parsed.entries) parsed.entries = [];
  parsed.version = 1;
  return parsed;
}

export function writeMetadata(
  cwd: string,
  config: SupplywardenConfig,
  metadata: SecurityMetadata,
): string {
  const path = metadataPath(cwd, config);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(metadata, null, 2)}\n`);
  return path;
}

export function newEntryId(): string {
  return randomUUID();
}

export function findActiveByPackage(
  metadata: SecurityMetadata,
  pkg: string,
): MetadataEntry[] {
  return metadata.entries.filter(
    (e) => e.package === pkg && (e.status === "active" || e.status === "pending_verify"),
  );
}

export function findByGhsa(
  metadata: SecurityMetadata,
  pkg: string,
  ghsaId?: string,
): MetadataEntry | undefined {
  if (!ghsaId) return undefined;
  return metadata.entries.find(
    (e) =>
      e.package === pkg &&
      e.advisories.some((a) => a.ghsaId === ghsaId) &&
      e.status !== "resolved" &&
      e.status !== "superseded",
  );
}

export function validateMetadataShape(metadata: unknown): string[] {
  const errors: string[] = [];
  if (!metadata || typeof metadata !== "object") {
    return ["metadata is not an object"];
  }
  const m = metadata as SecurityMetadata;
  if (m.version !== 1) errors.push("version must be 1");
  if (!Array.isArray(m.entries)) errors.push("entries must be an array");
  for (const [i, entry] of (m.entries ?? []).entries()) {
    if (!entry.id) errors.push(`entries[${i}].id missing`);
    if (!entry.package) errors.push(`entries[${i}].package missing`);
    if (!entry.forcedVersion) errors.push(`entries[${i}].forcedVersion missing`);
    if (!Array.isArray(entry.advisories)) errors.push(`entries[${i}].advisories missing`);
  }
  return errors;
}
