#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
import { execFile } from "node:child_process";
import { runAnalyze, runFix } from "./commands/fix.js";
import { runCheck } from "./commands/check.js";
import { runDoctor } from "./commands/doctor.js";
import { runInit } from "./commands/init.js";
import { runReport } from "./commands/report.js";
import { runSync } from "./commands/sync.js";
import { runWhy } from "./commands/why.js";
import { runVerify } from "./commands/verify.js";
import { toMarkdown } from "./report/model.js";
import { writeHtml } from "./report/html.js";
import type { CommandResult } from "./types.js";

type GlobalOpts = {
  cwd?: string;
  html?: string | boolean;
  open?: boolean;
};

const program = new Command();

program
  .name("supplywarden")
  .description("Supply-chain governance for npm projects — triage, audited overrides, and compliance checks")
  .version("0.1.0");

withGlobals(program);

function withGlobals(cmd: Command): Command {
  return cmd
    .option("--cwd <dir>", "project directory", process.cwd())
    .option("--html [path]", "write HTML report")
    .option("--open", "open HTML report in the browser");
}

function globalsOf(cmd: Command): GlobalOpts {
  return cmd.optsWithGlobals() as GlobalOpts;
}

function cwdOf(cmd: Command): string {
  return resolve(globalsOf(cmd).cwd ?? process.cwd());
}

function emit(result: CommandResult, cmd: Command): never {
  const global = globalsOf(cmd);
  const md = toMarkdown(result.report);
  console.log(md);
  for (const msg of result.messages) {
    console.error(msg);
  }
  if (global.html !== undefined) {
    const path = typeof global.html === "string" ? global.html : "supplywarden-report.html";
    writeHtml(result.report, path);
    console.error(`HTML report: ${path}`);
    if (global.open && process.env.SUPPLYWARDEN_TEST !== "1" && process.env.VULNFIX_TEST !== "1") {
      const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
      execFile(opener, [path], () => undefined);
    }
  }
  process.exit(result.exitCode);
}

function auditFlag(opts: { audit?: boolean; skipAudit?: boolean }): boolean | undefined {
  if (opts.skipAudit) return false;
  if (opts.audit) return true;
  return undefined;
}

/** pnpm run try -- --cwd … forwards a literal "--" as first argv token. */
function argvForCommander(argv: string[]): string[] {
  if (argv[2] === "--") return [argv[0]!, argv[1]!, ...argv.slice(3)];
  return argv;
}

withGlobals(program.command("doctor").description("Check npm version, lockfile, metadata")).action(
  (_opts, cmd: Command) => {
    emit(runDoctor({ cwd: cwdOf(cmd) }), cmd);
  },
);

withGlobals(
  program.command("init").description("Import existing overrides into security-metadata.json"),
).action((_opts, cmd: Command) => {
  emit(runInit({ cwd: cwdOf(cmd) }), cmd);
});

withGlobals(
  program
    .command("analyze")
    .argument("[alert.json]", "Dependabot alert JSON; omit to use npm/pnpm audit when enabled")
    .option("--audit", "use package-manager audit when no alert file is given")
    .option("--skip-audit", "do not fall back to package-manager audit")
    .description("Analyze Dependabot alert(s) without writing"),
).action(async (alertPath: string | undefined, opts: { audit?: boolean; skipAudit?: boolean }, cmd: Command) => {
  emit(
    await runAnalyze({
      cwd: cwdOf(cmd),
      alertPath: alertPath ? resolve(alertPath) : undefined,
      enableAudit: auditFlag(opts),
    }),
    cmd,
  );
});

withGlobals(
  program
    .command("fix")
    .argument("[alert.json]", "Dependabot alert JSON; omit to use npm/pnpm audit when enabled")
    .option("--apply", "write metadata + package.json")
    .option("--yes", "accept impact warnings")
    .option("--audit", "use package-manager audit when no alert file is given")
    .option("--skip-audit", "do not fall back to package-manager audit")
    .description("Plan (and optionally apply) a fix"),
).action(
  async (
    alertPath: string | undefined,
    opts: { apply?: boolean; yes?: boolean; audit?: boolean; skipAudit?: boolean },
    cmd: Command,
  ) => {
    emit(
      await runFix({
        cwd: cwdOf(cmd),
        alertPath: alertPath ? resolve(alertPath) : undefined,
        apply: opts.apply,
        yes: opts.yes,
        skipInstall: true,
        enableAudit: auditFlag(opts),
      }),
      cmd,
    );
  },
);

withGlobals(
  program
    .command("check")
    .option("--strict", "exit 1 on overdue high/critical, drift, verify_failed, or new audit findings")
    .option("--apply", "resolve REMOVABLE/RESOLVED entries")
    .option("--yes", "apply without extra confirmation")
    .option("--audit", "run npm/pnpm/yarn audit for untracked findings")
    .option("--skip-audit", "skip audit even if enabled in config")
    .description("Classify existing overrides"),
).action(
  async (
    opts: { strict?: boolean; apply?: boolean; yes?: boolean; audit?: boolean; skipAudit?: boolean },
    cmd: Command,
  ) => {
    emit(
      await runCheck({
        cwd: cwdOf(cmd),
        strict: opts.strict,
        apply: opts.apply,
        yes: opts.yes,
        enableAudit: auditFlag(opts),
      }),
      cmd,
    );
  },
);

withGlobals(
  program
    .command("verify")
    .option("--apply", "drop overrides that verify confirmed as removable")
    .option("--skip-install", "probe without running npm/pnpm install")
    .description("Probe-remove REMOVABLE overrides: install + audit, then restore or --apply"),
).action(async (opts: { apply?: boolean; skipInstall?: boolean }, cmd: Command) => {
  emit(
    await runVerify({
      cwd: cwdOf(cmd),
      apply: opts.apply,
      skipInstall: opts.skipInstall,
    }),
    cmd,
  );
});

withGlobals(program.command("sync").description("Rewrite package.json overrides from metadata")).action(
  (_opts, cmd: Command) => {
    emit(runSync({ cwd: cwdOf(cmd) }), cmd);
  },
);

withGlobals(
  program.command("why").argument("<package>").description("Show who pulls in a package"),
).action((pkg: string, _opts, cmd: Command) => {
  emit(runWhy({ cwd: cwdOf(cmd), package: pkg }), cmd);
});

withGlobals(program.command("report").description("HTML/markdown dashboard from metadata")).action(async (_opts, cmd: Command) => {
  const result = await runReport({ cwd: cwdOf(cmd) });
  if (globalsOf(cmd).html === undefined) {
    const path = writeHtml(result.report, resolve(cwdOf(cmd), "supplywarden-report.html"));
    console.error(`HTML report: ${path}`);
  }
  emit(result, cmd);
});

program.parseAsync(argvForCommander(process.argv));
