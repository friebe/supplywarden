import { execFile, execFileSync, spawn, type ExecFileSyncOptionsWithStringEncoding } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import type { PackageManager } from "../types.js";

const execFileAsync = promisify(execFile);

export type ResolvedPm = {
  file: string;
  argsPrefix: string[];
  shell: boolean;
};

export type ResolvePmEnv = {
  platform?: NodeJS.Platform;
  execPath?: string;
  exists?: (path: string) => boolean;
};

/**
 * Resolve npm/pnpm/yarn so Windows .cmd shims do not throw spawn EINVAL
 * (Node 20+ refuses to exec batch files without shell).
 */
export function resolvePm(pm: PackageManager, env: ResolvePmEnv = {}): ResolvedPm {
  const platform = env.platform ?? process.platform;
  const execPath = env.execPath ?? process.execPath;
  const exists = env.exists ?? existsSync;
  const win = platform === "win32";
  const nodeDir = dirname(execPath);

  if (pm === "npm") {
    const npmCli = join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js");
    if (exists(npmCli)) {
      return { file: execPath, argsPrefix: [npmCli], shell: false };
    }
  } else {
    const corepack = join(nodeDir, "node_modules", "corepack", "dist", "corepack.js");
    if (exists(corepack)) {
      return { file: execPath, argsPrefix: [corepack, pm], shell: false };
    }
  }

  const shim = win ? `${pm}.cmd` : pm;
  const sibling = join(nodeDir, shim);
  return {
    file: exists(sibling) ? sibling : shim,
    argsPrefix: [],
    shell: win,
  };
}

type ExecOpts = {
  cwd?: string;
  timeout?: number;
  maxBuffer?: number;
  stdio?: "pipe" | "inherit";
};

function execOptions(bin: ResolvedPm, opts: ExecOpts): ExecFileSyncOptionsWithStringEncoding {
  return {
    cwd: opts.cwd,
    encoding: "utf8",
    maxBuffer: opts.maxBuffer ?? 20 * 1024 * 1024,
    timeout: opts.timeout ?? 120_000,
    windowsHide: true,
    shell: bin.shell,
  };
}

export async function execPm(
  pm: PackageManager,
  args: string[],
  opts: ExecOpts = {},
): Promise<{ stdout: string; stderr: string }> {
  const bin = resolvePm(pm);
  if (opts.stdio === "inherit") {
    await execPmInherit(bin, args, opts);
    return { stdout: "", stderr: "" };
  }
  const run = execFileAsync(bin.file, [...bin.argsPrefix, ...args], execOptions(bin, opts)) as Promise<{
    stdout: string | Buffer;
    stderr: string | Buffer;
  }>;
  try {
    const { stdout, stderr } = await run;
    return { stdout: String(stdout ?? ""), stderr: String(stderr ?? "") };
  } catch (err) {
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout === "string" && stdout.trim()) {
      return { stdout, stderr: String((err as { stderr?: string }).stderr ?? "") };
    }
    throw err;
  }
}

function execPmInherit(
  bin: ResolvedPm,
  args: string[],
  opts: ExecOpts,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin.file, [...bin.argsPrefix, ...args], {
      cwd: opts.cwd,
      stdio: "inherit",
      windowsHide: true,
      shell: bin.shell,
      timeout: opts.timeout ?? 300_000,
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${bin.file} ${args.join(" ")} exited ${code ?? "null"}`));
    });
  });
}

export function execPmSync(pm: PackageManager, args: string[], opts: ExecOpts = {}): string {
  const bin = resolvePm(pm);
  return execFileSync(bin.file, [...bin.argsPrefix, ...args], execOptions(bin, opts))
    .toString()
    .trim();
}
