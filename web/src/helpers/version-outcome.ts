import type { RollbackResult } from "@/lib/types";
/** HTTP 200 reports an attempt; the version is the enforcement outcome. */
export function checkedRollback(result: RollbackResult): RollbackResult {
  if (result.version.status !== "applied" && !result.rolled_back_to)
    throw new Error(result.version.error || "Rollback has not been confirmed applied");
  return result;
}
