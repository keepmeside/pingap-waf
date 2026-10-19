import { describe, it, expect } from "vitest";
import { policyPayload } from "@/helpers/policy-payload";
describe("policy payload", () => {
  for (const category of ["waf", "acl", "bot"]) {
    it(`creates ${category} and preserves engine-specific fields`, () => {
      const body = { enabled: true, unknown_future: { value: 3 } };
      expect(policyPayload(`${category}:strict`, body)).toEqual({
        ...body,
        category,
      });
      expect(body).not.toHaveProperty("category");
    });
  }
  it("does not silently overwrite conflicting category", () => {
    expect(() => policyPayload("waf:strict", { category: "acl" })).toThrow(
      /category/i,
    );
  });
  it("rejects incomplete entry names", () => {
    for (const n of ["waf", ":strict", "waf:"])
      expect(() => policyPayload(n, {})).toThrow();
  });
});
