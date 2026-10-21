import { describe, it, expect } from "vitest";
import { checkedRollback } from "@/helpers/version-outcome";
import type { RollbackResult } from "@/lib/types";
const result = (status: string, error: string | null = null, previous: string | null = null) => ({version:{id:"candidate",status,error},rolled_back_to:previous} as RollbackResult);
describe("rollback version outcome", () => {
  it("rejects a transport-successful rollback whose file validation failed", () => {
    expect(()=>checkedRollback(result("failed","challenge: secret_file unavailable"))).toThrow("secret_file unavailable");
    expect(()=>checkedRollback(result("pending"))).toThrow();
  });
  it("preserves applied outcomes and explicit fallback warnings", () => {
    expect(checkedRollback(result("applied")).version.status).toBe("applied");
    expect(checkedRollback(result("failed","verification failed","previous")).rolled_back_to).toBe("previous");
  });
});
