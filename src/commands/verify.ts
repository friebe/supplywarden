import { analyzeNpmGraph, resolvePackageManager } from "../graph/npm.js";
import {
  decide,
  formatUpgradeTargets,
  lookupFromRegistry,
  resolveUpgradeDecision,
} from "../decision/engine.js";
import { findingForSilentPin, readPins } from "./check.js";
import { deleteOverrideFromManifest } from "../metadata/sync.js";
import { createLiveAudit, filterFindings, findingsToGroups } from "../audit/client.js";
import { createLiveInstall } from "../install/client.js";
import { createLiveRegistry } from "../registry/verify.js";
import { rootUpgradeCommands } from "../fix/upgrade-command.js";
import { PROJECT_SNAPSHOT_FILES, restoreFiles, snapshotFiles } from "../util/snapshot.js";
import { nowIso } from "../util/time.js";
import { loadConfig } from "../config.js";
import type {
  AuditClient,
  CommandResult,
  Finding,
  InstallClient,
  RegistryClient,
} from "../types.js";

export async function runVerify(opts: {
  cwd: string;
  package?: string;
  apply?: boolean;
  skipInstall?: boolean;
  audit?: AuditClient;
  install?: InstallClient;
  registry?: RegistryClient;
}): Promise<CommandResult> {
  const cwd = opts.cwd;
  const config = loadConfig(cwd);
  const pkg = opts.package;
  const audit = opts.audit ?? createLiveAudit();
  const install = opts.install ?? createLiveInstall();
  const registry = opts.registry ?? createLiveRegistry(cwd);

  const pins = readPins(cwd);
  let targets = pkg ? pins.filter((pin) => pin.package === pkg) : [];
  if (!pkg) {
    const result = await audit.audit(cwd);
    const listed = new Set(
      findingsToGroups(filterFindings(result.vulnerabilities, config.audit.minSeverity)).map(
        (g) => g.package,
      ),
    );
    targets = pins.filter(
      (pin) =>
        !listed.has(pin.package) &&
        findingForSilentPin(cwd, pin.package, pin.version).action === "drop",
    );
  }

  if (!targets.length) {
    const messages = pkg
      ? [
          `verify: no override for ${pkg} in package.json`,
          `Inspect with \`supplywarden why ${pkg}\`.`,
        ]
      : [
          "verify: no leftover overrides. Pass a package to probe that pin (`supplywarden verify qs`).",
        ];
    return {
      exitCode: pkg ? 1 : 0,
      messages,
      report: {
        title: "verify",
        generatedAt: nowIso(),
        cwd,
        summary: { probed: 0 },
        entries: [],
      },
    };
  }

  const snap = snapshotFiles(cwd, PROJECT_SNAPSHOT_FILES);
  const probed: Finding[] = [];
  const messages: string[] = [
    pkg
      ? `verify ${pkg} — drop, install, audit`
      : `verify — ${targets.length} override(s) the audit does not list`,
  ];

  for (const pin of targets) {
    restoreFiles(cwd, snap);
    deleteOverrideFromManifest(cwd, pin.package);
    if (!opts.skipInstall) {
      const installed = await install.install(cwd);
      if (!installed.ok) {
        restoreFiles(cwd, snap);
        probed.push({
          package: pin.package,
          severity: "unknown",
          advisories: [],
          installed: [],
          roots: [],
          chains: [],
          action: "drop",
          forcedVersion: pin.version,
          summary: `Install failed — override stays. ${installed.error ?? "install failed"}`,
          commands: [`supplywarden verify ${pin.package}`],
          outcome: "failed",
        });
        messages.push(`${pin.package}: install failed`);
        continue;
      }
    }

    const auditResult = await audit.audit(cwd);
    const still = filterFindings(auditResult.vulnerabilities, config.audit.minSeverity).some(
      (f) => f.package === pin.package,
    );
    restoreFiles(cwd, snap);

    if (still || auditResult.error) {
      const graph = analyzeNpmGraph(cwd, pin.package);
      const groupAdvisories =
        findingsToGroups(
          filterFindings(auditResult.vulnerabilities, config.audit.minSeverity).filter(
            (f) => f.package === pin.package,
          ),
        )[0]?.advisories ?? [];
      const decision = await resolveUpgradeDecision(
        decide({ graph, advisories: groupAdvisories, config }),
        lookupFromRegistry(registry),
        {
          vulnPackage: pin.package,
          advisories: groupAdvisories,
          chains: graph.chains,
          dependencyKind: graph.dependencyKind,
          directs: graph.directs,
        },
      );
      const pm = resolvePackageManager(cwd);
      const commands =
        decision.strategy === "upgrade"
          ? rootUpgradeCommands(pm, decision.upgradeTargets ?? []).map((c) => c.display)
          : [`supplywarden why ${pin.package}`];
      const why = auditResult.error
        ? `audit failed: ${auditResult.error}`
        : "audit still reports it";
      const bump = formatUpgradeTargets(decision);
      probed.push({
        package: pin.package,
        severity: "unknown",
        advisories: groupAdvisories,
        installed: graph.versions,
        roots: graph.roots.map((r) => `${r.name}@${r.version}`),
        chains: graph.chains.map((c) => c.path.join(" → ")),
        action: decision.strategy === "upgrade" ? "upgrade" : "override",
        forcedVersion: pin.version,
        upgradeTargets: decision.upgradeTargets,
        summary: `Keep the override — ${why}.${bump ? ` ${bump}.` : ""}`,
        commands,
        outcome: "keep",
      });
      messages.push(`${pin.package}: keep — ${why}`);
      continue;
    }

    probed.push({
      package: pin.package,
      severity: "unknown",
      advisories: [],
      installed: [],
      roots: [],
      chains: [],
      action: "drop",
      forcedVersion: pin.version,
      summary: opts.apply
        ? `Override ${pin.package}@${pin.version} removed.`
        : `Override ${pin.package}@${pin.version} can go. Pass --apply to remove it.`,
      commands: opts.apply ? [] : [`supplywarden verify ${pin.package} --apply`],
      outcome: "removable",
    });
    messages.push(`${pin.package}: can be removed`);
  }

  restoreFiles(cwd, snap);
  const removable = probed.filter((p) => p.outcome === "removable");
  if (opts.apply && removable.length) {
    for (const item of removable) deleteOverrideFromManifest(cwd, item.package);
    messages.push(`Removed ${removable.length} override(s) from package.json`);
  } else if (!opts.apply && removable.length) {
    messages.push("Dry-run: pass --apply to drop the overrides audit no longer needs");
  }

  if (!opts.skipInstall && !opts.apply) {
    await install.install(cwd);
  }

  return {
    exitCode: probed.some((p) => p.outcome === "failed") ? 1 : 0,
    messages,
    writtenFiles: opts.apply && removable.length ? ["package.json"] : undefined,
    report: {
      title: "verify",
      generatedAt: nowIso(),
      cwd,
      summary: {
        probed: probed.length,
        removable: removable.length,
        keep: probed.filter((p) => p.outcome === "keep").length,
      },
      entries: probed,
    },
  };
}
