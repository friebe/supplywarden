import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURES_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../fixtures");

export async function withFixture(
  fixtureName: string,
  fn: (projectDir: string) => Promise<void>,
): Promise<void> {
  const src = join(FIXTURES_ROOT, fixtureName);
  const dest = await mkdtemp(join(tmpdir(), "supplywarden-"));
  await cp(src, dest, { recursive: true });
  try {
    await fn(dest);
  } finally {
    await rm(dest, { recursive: true, force: true });
  }
}

export function fixtureDir(name: string): string {
  return join(FIXTURES_ROOT, name);
}
