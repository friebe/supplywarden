import type { PackageManager } from "../types.js";

export type UpgradeTarget = { name: string; from?: string; to?: string };

export type RootUpgradeCommand = {
  file: string;
  args: string[];
  display: string;
  kind: "nx" | "install";
};

/** Workspace migrate is only for the `nx` CLI package, not @nx/* plugins. */
export function isNxCli(name: string): boolean {
  return name === "nx";
}

/** `npm install lodash@x` then `npx nx migrate nx@y` — never drop the non-nx roots. */
export function rootUpgradeCommands(
  pm: PackageManager,
  targets: UpgradeTarget[],
): RootUpgradeCommand[] {
  const nx = targets.find((t) => isNxCli(t.name));
  const rest = targets.filter((t) => !isNxCli(t.name) && t.to);
  const commands: RootUpgradeCommand[] = [];
  const install = installCommand(pm, rest);
  if (install) commands.push(install);
  if (nx) commands.push(nxMigrateCommand(nx));
  return commands;
}

export function rootUpgradeCommand(
  pm: PackageManager,
  targets: UpgradeTarget[],
): RootUpgradeCommand | undefined {
  return rootUpgradeCommands(pm, targets)[0];
}

export function quotedUpgradeCommands(commands: RootUpgradeCommand[]): string {
  return commands.map((c) => `\`${c.display}\``).join(" then ");
}

function nxMigrateCommand(nx: UpgradeTarget): RootUpgradeCommand {
  const spec = nx.to ? `nx@${nx.to}` : "latest";
  return {
    file: "npx",
    args: ["nx", "migrate", spec],
    display: `npx nx migrate ${spec}`,
    kind: "nx",
  };
}

function installCommand(pm: PackageManager, targets: UpgradeTarget[]): RootUpgradeCommand | undefined {
  const specs = targets.map((t) => `${t.name}@${t.to}`);
  if (!specs.length) return undefined;
  if (pm === "npm") {
    return {
      file: "npm",
      args: ["install", ...specs],
      display: `npm install ${specs.join(" ")}`,
      kind: "install",
    };
  }
  return {
    file: pm,
    args: ["add", ...specs],
    display: `${pm} add ${specs.join(" ")}`,
    kind: "install",
  };
}
