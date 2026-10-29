import type { PackageManager } from "../types.js";

export type UpgradeTarget = { name: string; from?: string; to?: string };

export type RootUpgradeCommand = {
  file: string;
  args: string[];
  display: string;
  kind: "nx" | "migrate" | "install";
};

type MigrateTool = {
  owns: (name: string) => boolean;
  command: (members: UpgradeTarget[]) => RootUpgradeCommand;
};

/**
 * Packages whose upgrade is a migration CLI, not `npm install` of one name.
 * Members of one tool share a single command so a peer set moves together.
 */
const MIGRATE_TOOLS: MigrateTool[] = [
  {
    owns: (name) => name === "nx",
    command: (members) => nxMigrateCommand(members[0]!),
  },
  {
    owns: (name) => name.startsWith("@angular/"),
    command: (members) => {
      const specs = members.map((member) => `${member.name}@${member.to}`);
      return {
        file: "npx",
        args: ["ng", "update", ...specs],
        display: `npx ng update ${specs.join(" ")}`,
        kind: "migrate",
      };
    },
  },
  {
    owns: (name) => name === "storybook" || name.startsWith("@storybook/"),
    command: (members) => {
      const cli = members.find((member) => member.name === "storybook") ?? members[0]!;
      const spec = cli.to ? `storybook@${cli.to}` : "storybook@latest";
      return {
        file: "npx",
        args: [spec, "upgrade"],
        display: `npx ${spec} upgrade`,
        kind: "migrate",
      };
    },
  },
];

/** Workspace migrate is only for the `nx` CLI package, not @nx/* plugins. */
export function isNxCli(name: string): boolean {
  return name === "nx";
}

/** More than one package has to move, so the command is the whole set. */
export function groupUpgradeNote(targets: UpgradeTarget[]): string | undefined {
  const names = targets.filter((target) => target.to).map((target) => target.name);
  if (names.length < 2) return undefined;
  return `Update ${names.join(" and ")} together, not one package at a time.`;
}

/** `npm install lodash@x` then one migration CLI for each family — never one install per sibling. */
export function rootUpgradeCommands(
  pm: PackageManager,
  targets: UpgradeTarget[],
): RootUpgradeCommand[] {
  const claimed = new Set<string>();
  const grouped: RootUpgradeCommand[] = [];
  for (const tool of MIGRATE_TOOLS) {
    const members = targets.filter((target) => target.to && tool.owns(target.name));
    if (!members.length) continue;
    for (const member of members) claimed.add(member.name);
    grouped.push(tool.command(members));
  }
  const rest = targets.filter((target) => target.to && !claimed.has(target.name));
  const commands: RootUpgradeCommand[] = [];
  const install = installCommand(pm, rest);
  if (install) commands.push(install);
  commands.push(...grouped);
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

function installCommand(
  pm: PackageManager,
  targets: UpgradeTarget[],
): RootUpgradeCommand | undefined {
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
