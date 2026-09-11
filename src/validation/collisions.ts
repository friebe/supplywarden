import type { MetadataEntry, SecurityMetadata } from "../types.js";

export function dedupeOrSupersede(
  metadata: SecurityMetadata,
  incoming: MetadataEntry,
): { metadata: SecurityMetadata; supersededIds: string[] } {
  const supersededIds: string[] = [];
  const ghsaIds = incoming.advisories.map((a) => a.ghsaId).filter(Boolean);

  metadata.entries = metadata.entries.map((entry) => {
    if (entry.id === incoming.id) return entry;
    if (entry.status === "resolved" || entry.status === "superseded") return entry;

    const samePackage = entry.package === incoming.package;
    const sameGhsa =
      ghsaIds.length > 0 &&
      entry.advisories.some((a) => a.ghsaId && ghsaIds.includes(a.ghsaId));

    if (samePackage && (sameGhsa || entry.forcedVersion !== incoming.forcedVersion)) {
      supersededIds.push(entry.id);
      return {
        ...entry,
        status: "superseded",
        resolvedAt: incoming.createdAt,
        resolution: `superseded by ${incoming.id}`,
      };
    }
    return entry;
  });

  const existingIdx = metadata.entries.findIndex((e) => e.id === incoming.id);
  if (existingIdx >= 0) metadata.entries[existingIdx] = incoming;
  else metadata.entries.push(incoming);

  return { metadata, supersededIds };
}

export function findDuplicate(
  metadata: SecurityMetadata,
  pkg: string,
  ghsaId?: string,
): MetadataEntry | undefined {
  return metadata.entries.find((e) => {
    if (e.package !== pkg) return false;
    if (e.status === "resolved" || e.status === "superseded") return false;
    if (!ghsaId) return true;
    return e.advisories.some((a) => a.ghsaId === ghsaId);
  });
}
