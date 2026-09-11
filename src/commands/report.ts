import { runCheck } from "./check.js";
import type { CommandResult } from "../types.js";

export async function runReport(opts: { cwd: string }): Promise<CommandResult> {
  const result = await runCheck({ cwd: opts.cwd });
  result.report.title = "supplywarden report";
  return result;
}
