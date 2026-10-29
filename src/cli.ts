#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
import { execFile } from "node:child_process";
import { runFix } from "./commands/fix.js";
import { runCheck } from "./commands/check.js";
import { runDoctor } from "./commands/doctor.js";
import { runReport } from "./commands/report.js";
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
  .description(
    "Show transitive npm audit findings with the root that pulls them in and the next command",
  )
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

function openReport(filePath: string): void {
  const abs = resolve(filePath);
  if (process.platform === "darwin") {
    execFile("open", [abs], () => undefined);
  } else if (process.platform === "win32") {
    execFile("cmd.exe", ["/c", "start", "", abs], { windowsHide: true }, () => undefined);
  } else {
    execFile("xdg-open", [abs], () => undefined);
  }
}

function emit(result: CommandResult, cmd: Command): never {
  const global = globalsOf(cmd);
  const md = toMarkdown(result.report);
  console.log(md);
  for (const msg of result.messages) {
    console.error(msg);
  }
  const htmlPath =
    typeof global.html === "string"
      ? global.html
      : global.html !== undefined || global.open
        ? "supplywarden-report.html"
        : undefined;
  if (htmlPath) {
    writeHtml(result.report, htmlPath);
    console.error(`HTML report: ${htmlPath}`);
    if (global.open && process.env.SUPPLYWARDEN_TEST !== "1") {
      openReport(htmlPath);
    }
  }
  process.exit(result.exitCode);
}

/** pnpm run try -- --cwd … forwards a literal "--" as first argv token. */
function argvForCommander(argv: string[]): string[] {
  if (argv[2] === "--") return [argv[0]!, argv[1]!, ...argv.slice(3)];
  return argv;
}

withGlobals(program.command("doctor").description("Check the package manager and lockfile")).action(
  (_opts, cmd: Command) => {
    emit(runDoctor({ cwd: cwdOf(cmd) }), cmd);
  },
);

withGlobals(
  program
    .command("fix")
    .argument("[package]", "only this package; omit to plan every open finding")
    .option(
      "--apply",
      "write package.json overrides, or run a root upgrade via the package manager",
    )
    .option("--skip-install", "do not run npm/pnpm/yarn install")
    .description("Plan a fix from live audit; --apply writes the pin"),
).action(
  async (
    pkg: string | undefined,
    opts: { apply?: boolean; skipInstall?: boolean },
    cmd: Command,
  ) => {
    emit(
      await runFix({
        cwd: cwdOf(cmd),
        package: pkg,
        apply: opts.apply,
        skipInstall: Boolean(opts.skipInstall),
      }),
      cmd,
    );
  },
);

withGlobals(
  program
    .command("check")
    .option("--strict", "exit 1 when a finding still needs an upgrade or a pin")
    .description("Audit and print one next command per transitive finding"),
).action(async (opts: { strict?: boolean }, cmd: Command) => {
  emit(
    await runCheck({
      cwd: cwdOf(cmd),
      strict: opts.strict,
    }),
    cmd,
  );
});

withGlobals(
  program
    .command("verify")
    .argument("[package]", "probe this override; omit to probe overrides the audit does not list")
    .option("--apply", "remove overrides the audit no longer needs")
    .option("--skip-install", "probe without running npm/pnpm install")
    .description("Drop an override, install, audit, then restore or keep the drop"),
).action(
  async (
    pkg: string | undefined,
    opts: { apply?: boolean; skipInstall?: boolean },
    cmd: Command,
  ) => {
    emit(
      await runVerify({
        cwd: cwdOf(cmd),
        package: pkg,
        apply: opts.apply,
        skipInstall: opts.skipInstall,
      }),
      cmd,
    );
  },
);

withGlobals(
  program.command("why").argument("<package>").description("Show who pulls in a package"),
).action((pkg: string, _opts, cmd: Command) => {
  emit(runWhy({ cwd: cwdOf(cmd), package: pkg }), cmd);
});

withGlobals(program.command("report").description("Same picture as check, written as HTML")).action(
  async (_opts, cmd: Command) => {
    const result = await runReport({ cwd: cwdOf(cmd) });
    if (globalsOf(cmd).html === undefined) {
      const path = writeHtml(result.report, resolve(cwdOf(cmd), "supplywarden-report.html"));
      console.error(`HTML report: ${path}`);
    }
    emit(result, cmd);
  },
);

void program.parseAsync(argvForCommander(process.argv));
