import { analyzeNpmGraph } from "../graph/npm.js";
import { stillVulnerable } from "../decision/engine.js";
import { loadConfig } from "../config.js";
import { classifyEntry } from "../check/classify.js";
import { readMetadata, writeMetadata } from "../metadata/store.js";
import { syncOverridesToPackageJson } from "../metadata/sync.js";
import { createLiveAudit, filterFindings } from "../audit/client.js";
import { createLiveInstall } from "../install/client.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { nowIso } from "../util/time.js";
import type {
  AuditClient,
  CheckEntry,
  CheckStatus,
  CommandResult,
  InstallClient,
} from "../types.js";

export async function runVerify(opts: {
  cwd: string;
  apply?: boolean;
  skipInstall?: boolean;
  audit?: AuditClient;
  install?: InstallClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const metadata = readMetadata(cwd, config);
  const active = metadata.entries.filter((e) => e.status === "active");
  const classified = active.map((e) => classifyEntry(cwd, e));
  const candidates = classified.filter((c) =>
    ["REMOVABLE", "RESOLVED"].includes(c.status as CheckStatus),
  );

  if (!candidates.length) {
    return {
      exitCode: 0,
      messages: ["verify: no REMOVABLE/RESOLVED overrides to probe"],
      report: {
        title: "supplywarden verify – nothing to probe",
        generatedAt: nowIso(),
        cwd,
        summary: { probed: 0 },
        entries: classified,
      },
    };
  }

  const audit = opts.audit ?? createLiveAudit();
  const install = opts.install ?? createLiveInstall();
  const files = [...PROJECT_SNAPSHOT_FILES, config.metadataPath];
  const snap = snapshotFiles(cwd, files);
  const probed: CheckEntry[] = [];
  const messages: string[] = [`supplywarden verify – ${candidates.length} candidate(s)`];
  let needResync = false;

  for (const candidate of candidates) {
    restoreFiles(cwd, snap);
    const working = readMetadata(cwd, config);
    const entry = working.entries.find((e) => e.id === candidate.entry.id);
    if (!entry) continue;
    entry.status = "resolved";
    entry.resolvedAt = nowIso();
    entry.resolution = "verify-probe";
    writeMetadata(cwd, config, working);
    syncOverridesToPackageJson(cwd, working, entry.manifestPath);

    if (!opts.skipInstall) {
      const installed = await install.install(cwd);
      if (!installed.ok) {
        restoreFiles(cwd, snap);
        probed.push({
          ...candidate,
          verifyOutcome: "VERIFY_FAILED",
          suggestedAction: `Install failed — keep override (${installed.error ?? "install failed"}); retry with \`supplywarden verify\``,
        });
        messages.push(`${candidate.entry.package}: KEEP (install failed)`);
        continue;
      }
      needResync = true;
    }

    const graph = analyzeNpmGraph(cwd, candidate.entry.package);
    const auditResult = await audit.audit(cwd);
    const pkgFindings = filterFindings(auditResult.vulnerabilities, config.audit.minSeverity).filter(
      (f) => f.package === candidate.entry.package,
    );
    const stillVuln = graph.versions.filter((v) =>
      candidate.entry.advisories.length
        ? stillVulnerable(v, candidate.entry.advisories)
        : false,
    );

    const keep =
      Boolean(auditResult.error) ||
      pkgFindings.length > 0 ||
      stillVuln.length > 0;

    restoreFiles(cwd, snap);

    if (keep) {
      const why = auditResult.error
        ? `audit failed: ${auditResult.error}`
        : pkgFindings.length
          ? `audit still reports ${pkgFindings.length} finding(s)`
          : `lockfile still has vulnerable version(s): ${stillVuln.join(", ")}`;
      probed.push({
        ...candidate,
        verifyOutcome: "KEEP",
        suggestedAction: `Keep override — ${why}; inspect with \`supplywarden why ${candidate.entry.package}\``,
      });
      messages.push(`${candidate.entry.package}: KEEP (${why})`);
    } else {
      probed.push({
        ...candidate,
        verifyOutcome: "CONFIRMED_REMOVABLE",
        suggestedAction: graph.inTree
          ? "Verify confirmed: override can be removed (tree is no longer vulnerable) — run `supplywarden verify --apply`"
          : "Verify confirmed: package is no longer in the tree — run `supplywarden verify --apply`",
      });
      messages.push(`${candidate.entry.package}: CONFIRMED_REMOVABLE`);
    }
  }

  restoreFiles(cwd, snap);

  if (needResync && !opts.skipInstall && !opts.apply) {
    await install.install(cwd);
  }

  let written: string[] = [];
  const confirmed = probed.filter((p) => p.verifyOutcome === "CONFIRMED_REMOVABLE");
  if (opts.apply && confirmed.length) {
    const next = readMetadata(cwd, config);
    for (const item of confirmed) {
      const entry = next.entries.find((e) => e.id === item.entry.id);
      if (!entry) continue;
      entry.status = "resolved";
      entry.resolvedAt = nowIso();
      entry.resolution = "verify-confirmed";
    }
    writeMetadata(cwd, config, next);
    syncOverridesToPackageJson(cwd, next);
    written = [config.metadataPath, "package.json"];
    messages.push(`Applied ${confirmed.length} confirmed removal(s)`);
  } else if (!opts.apply && confirmed.length) {
    messages.push("Dry-run: pass --apply to drop confirmed overrides");
  }

  const failed = probed.some((p) => p.verifyOutcome === "VERIFY_FAILED");
  const kept = probed.filter((p) => p.verifyOutcome === "KEEP").length;

  return {
    exitCode: failed ? 1 : 0,
    messages,
    writtenFiles: written,
    report: {
      title: `supplywarden verify – ${probed.length} probed`,
      generatedAt: nowIso(),
      cwd,
      summary: {
        probed: probed.length,
        confirmed: confirmed.length,
        keep: kept,
        verifyFailed: probed.filter((p) => p.verifyOutcome === "VERIFY_FAILED").length,
      },
      entries: probed,
    },
  };
}
