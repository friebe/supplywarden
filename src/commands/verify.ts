import { analyzeNpmGraph } from "../graph/npm.js";
import { stillVulnerable } from "../decision/engine.js";
import { loadConfig } from "../config.js";
import { listOverridesToProbe } from "./check.js";
import { readMetadata, writeMetadata } from "../metadata/store.js";
import { deleteOverrideFromManifest, syncOverridesToPackageJson } from "../metadata/sync.js";
import { createLiveAudit, filterFindings } from "../audit/client.js";
import { createLiveInstall } from "../install/client.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { nowIso } from "../util/time.js";
import type { AuditClient, CheckEntry, CommandResult, InstallClient } from "../types.js";

function leftoverHeuristic(entry: CheckEntry): boolean {
  return (
    entry.removableReason === "not-in-tree" ||
    entry.removableReason === "already-at-patched"
  );
}

function overrideConflictPackage(error: string): string | undefined {
  const match = error.match(/Override for ([^\s@]+)@/i);
  return match?.[1];
}

export async function runVerify(opts: {
  cwd: string;
  package?: string;
  apply?: boolean;
  skipInstall?: boolean;
  audit?: AuditClient;
  install?: InstallClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const pkg = opts.package;
  const candidates = listOverridesToProbe(cwd, config, pkg);
  const classified = candidates;

  if (!candidates.length) {
    const messages = pkg
      ? [
          `verify: no override for ${pkg} in package.json or security-metadata.json`,
          `Inspect with \`supplywarden why ${pkg}\`. Without a package name, verify only probes REMOVABLE leftovers.`,
        ]
      : [
          "verify: no REMOVABLE/RESOLVED overrides to probe",
          "Pass a package to try dropping that one override (`supplywarden verify qs`), even if check has not marked it REMOVABLE.",
        ];
    return {
      exitCode: pkg ? 1 : 0,
      messages,
      report: {
        title: pkg ? `supplywarden verify ${pkg} – nothing to probe` : "supplywarden verify – nothing to probe",
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
  const messages: string[] = [
    pkg
      ? `supplywarden verify ${pkg} – probing 1 override (drop → install → audit)`
      : `supplywarden verify – ${candidates.length} candidate(s)`,
  ];
  let needResync = false;

  for (const candidate of candidates) {
    restoreFiles(cwd, snap);
    const working = readMetadata(cwd, config);
    const entry = working.entries.find((e) => e.id === candidate.entry.id);
    if (entry) {
      entry.status = "resolved";
      entry.resolvedAt = nowIso();
      entry.resolution = "verify-probe";
      writeMetadata(cwd, config, working);
      syncOverridesToPackageJson(cwd, working, entry.manifestPath);
    } else {
      deleteOverrideFromManifest(cwd, candidate.entry.package);
    }

    let installedOk = opts.skipInstall || leftoverHeuristic(candidate);
    if (!opts.skipInstall && !leftoverHeuristic(candidate)) {
      const installed = await install.install(cwd);
      if (!installed.ok) {
        const conflictPkg = overrideConflictPackage(installed.error ?? "");
        const unrelated = Boolean(conflictPkg && conflictPkg !== candidate.entry.package);
        restoreFiles(cwd, snap);
        if (!unrelated) {
          probed.push({
            ...candidate,
            verifyOutcome: "VERIFY_FAILED",
            suggestedAction: `Install failed — keep override (${installed.error ?? "install failed"}); retry with \`supplywarden verify ${candidate.entry.package}\``,
          });
          messages.push(`${candidate.entry.package}: VERIFY_FAILED (install failed)`);
          continue;
        }
        messages.push(
          `${candidate.entry.package}: install skipped (unrelated override conflict: ${conflictPkg})`,
        );
      } else {
        installedOk = true;
        needResync = true;
      }
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
      pkgFindings.length > 0 ||
      stillVuln.length > 0 ||
      (Boolean(auditResult.error) && !leftoverHeuristic(candidate) && installedOk);

    restoreFiles(cwd, snap);

    if (keep) {
      const why = pkgFindings.length
        ? `audit still reports ${pkgFindings.length} finding(s)`
        : stillVuln.length
          ? `lockfile still has vulnerable version(s): ${stillVuln.join(", ")}`
          : `audit failed: ${auditResult.error}`;
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
          ? `Verify confirmed: override can be removed — run \`supplywarden verify ${candidate.entry.package} --apply\``
          : `Verify confirmed: package is no longer in the tree — run \`supplywarden verify ${candidate.entry.package} --apply\``,
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
      if (entry) {
        entry.status = "resolved";
        entry.resolvedAt = nowIso();
        entry.resolution = "verify-confirmed";
      }
      deleteOverrideFromManifest(cwd, item.entry.package);
    }
    writeMetadata(cwd, config, next);
    written = [config.metadataPath, "package.json"];
    messages.push(`Applied ${confirmed.length} confirmed removal(s)`);
  } else if (opts.apply && !confirmed.length) {
    messages.push(
      "verify --apply: nothing confirmed as removable (install/audit kept every candidate). See KEEP/VERIFY_FAILED above.",
    );
  } else if (!opts.apply && confirmed.length) {
    messages.push("Dry-run: pass --apply to drop confirmed overrides");
  }

  const failed = probed.some((p) => p.verifyOutcome === "VERIFY_FAILED");

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
        keep: probed.filter((p) => p.verifyOutcome === "KEEP").length,
        verifyFailed: probed.filter((p) => p.verifyOutcome === "VERIFY_FAILED").length,
      },
      entries: probed,
    },
  };
}
