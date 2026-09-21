import type { DependencyKind } from "../types.js";

type LockFlags = {
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
};

export function inferDependencyKind(opts: {
  pkgName: string;
  copies: LockFlags[];
  rootNames: string[];
  rootDependencies?: Record<string, string>;
  rootDevDependencies?: Record<string, string>;
  rootOptionalDependencies?: Record<string, string>;
}): DependencyKind {
  const prod = opts.rootDependencies ?? {};
  const dev = opts.rootDevDependencies ?? {};
  const opt = opts.rootOptionalDependencies ?? {};
  const inProd = (name: string) => name in prod;
  const inDev = (name: string) => name in dev;
  const inOpt = (name: string) => name in opt;

  if (inProd(opts.pkgName) || opts.rootNames.some(inProd)) return "production";

  if (opts.copies.length) {
    const allDev = opts.copies.every((c) => c.dev === true);
    const allOpt = opts.copies.every((c) => c.optional === true || c.devOptional === true);
    const anyUnflagged = opts.copies.some((c) => !c.dev && !c.optional && !c.devOptional);
    if (allDev) return "development";
    if (allOpt) return "optional";
    if (anyUnflagged && (opts.rootNames.length === 0 || opts.rootNames.some(inProd))) {
      return "production";
    }
  }

  if (opts.rootNames.length > 0 && opts.rootNames.every(inOpt) && !opts.rootNames.some(inProd)) {
    return "optional";
  }
  if (inDev(opts.pkgName) || (opts.rootNames.length > 0 && opts.rootNames.every(inDev))) {
    return "development";
  }
  if (inOpt(opts.pkgName)) return "optional";
  return "production";
}

export function dependencyKindLabel(kind?: DependencyKind): string {
  if (kind === "development" || kind === "optional") return kind;
  return "";
}

export function mergeDependencyKind(a?: DependencyKind, b?: DependencyKind): DependencyKind | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a === "production" || b === "production") return "production";
  if (a === b) return a;
  return "production";
}
