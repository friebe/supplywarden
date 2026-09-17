import type { PackageManager } from "../types.js";

export type UpgradeTarget = { name: string; from?: string; to?: string };

export type RootUpgradeCommand = {
  file: string;
  args: string[];
  display: string;
  kind: "nx" | "install";
};

export function isNxPackage(name: string): boolean {
  return name === "nx" || name.startsWith("@nx/");
}

export function rootUpgradeCommand(
  pm: PackageManager,
  targets: UpgradeTarget[],
): RootUpgradeCommand | undefined {
  const nx = targets.find((t) => isNxPackage(t.name));
  if (nx) {
    const spec = nx.to ? `nx@${nx.to}` : "latest";
    return {
      file: "npx",
      args: ["nx", "migrate", spec],
      display: `npx nx migrate ${spec}`,
      kind: "nx",
    };
  }

  const specs = targets.filter((t) => t.to).map((t) => `${t.name}@${t.to}`);
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
