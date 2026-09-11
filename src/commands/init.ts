import { loadConfig } from "../config.js";
import { analyzeNpmGraph } from "../graph/npm.js";
import { importOverridesFromPackageJson } from "../metadata/import.js";
import { emptyMetadata, readMetadata, writeMetadata } from "../metadata/store.js";
import { nowIso } from "../util/time.js";
import type { CommandResult } from "../types.js";
import { emptyReport } from "../report/model.js";

export function runInit(opts: { cwd: string }): CommandResult {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const existing = readMetadata(cwd, config);
  if (existing.entries.length > 0) {
    return {
      exitCode: 0,
      messages: [`security-metadata.json already has ${existing.entries.length} entries – skip`],
      report: {
        ...emptyReport(cwd, "init: skipped"),
        summary: { imported: 0, existing: existing.entries.length },
      },
    };
  }

  const entries = importOverridesFromPackageJson(cwd, config, (pkg) => analyzeNpmGraph(cwd, pkg));
  const metadata = emptyMetadata();
  metadata.entries = entries;
  writeMetadata(cwd, config, metadata);

  const needsReview = entries.filter((e) => e.needsReview).length;
  const messages = [
    `${entries.length} overrides imported from package.json`,
    needsReview ? `${needsReview} entries missing advisory (needsReview)` : "all entries have graph context",
    "security-metadata.json created",
  ];

  return {
    exitCode: 0,
    messages,
    writtenFiles: [config.metadataPath],
    report: {
      title: "init",
      generatedAt: nowIso(),
      cwd,
      summary: { imported: entries.length, needsReview },
      entries: entries.map((entry) => ({
        entry,
        status: "OK" as const,
        statuses: ["OK" as const],
        suggestedAction: `Review imported override — run \`supplywarden why ${entry.package}\``,
        issues: [],
      })),
    },
  };
}
