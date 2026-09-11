import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type FileSnapshot = Record<string, string | null>;

export const PROJECT_SNAPSHOT_FILES = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
];

export function snapshotFiles(cwd: string, files: string[]): FileSnapshot {
  const out: FileSnapshot = {};
  for (const file of files) {
    const path = join(cwd, file);
    out[file] = existsSync(path) ? readFileSync(path, "utf8") : null;
  }
  return out;
}

export function restoreFiles(cwd: string, snap: FileSnapshot): void {
  for (const [file, content] of Object.entries(snap)) {
    if (content === null) continue;
    writeFileSync(join(cwd, file), content);
  }
}
