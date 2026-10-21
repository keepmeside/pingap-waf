import { describe, it, expect } from "vitest";
import { bindingFromEntry, bindingKey, rateSummary, challengePayload } from "@/helpers/policy-controls";
import { policyPayload } from "@/helpers/policy-payload";
describe("policy controls", () => {
  it("roundtrips every supported binding without reordering or losing entries", () => {
    for (const category of ["waf","acl","bot","challenge","behaviour","adaptive","limit"]) {
      const binding=bindingFromEntry(`${category}:edge:one`);
      expect(binding).not.toBeNull();expect(bindingKey(binding!)).toBe(`${category}:edge:one`);
    }
    expect(bindingFromEntry("unknown:profile")).toBeNull();
  });
  it("retains unknown fields and omits inspection metadata from challenge mutations", () => {
    const existing={category:"challenge",secret_configured:true,secret_source:{kind:"literal"},remark:"retained",enabled:true};
    const payload=challengePayload(existing,{difficulty:3},"");
    expect(payload).toEqual({category:"challenge",remark:"retained",enabled:true,difficulty:3});
    expect(policyPayload("challenge:edge",existing)).toEqual({config:{category:"challenge",remark:"retained",enabled:true}});
    expect(challengePayload(existing,{},"key-v2")).toEqual({category:"challenge",remark:"retained",enabled:true,secret_file:"key-v2"});
    expect(()=>challengePayload(existing,{},"../key")).toThrow();
    expect(()=>challengePayload(existing,{},"key..v2")).toThrow();
  });
  it("omits an unchanged or cleared file source so canonical state wins after rollback", () => {
    const stale = {category:"challenge",secret_file:"key-v2",secret_configured:true,remark:"retained"};
    expect(challengePayload(stale,{difficulty:3},"key-v2")).toEqual({category:"challenge",remark:"retained",difficulty:3});
    expect(challengePayload(stale,{},"")).not.toHaveProperty("secret_file");
    expect(challengePayload(stale,{},"key-v3").secret_file).toBe("key-v3");
  });
  it("reports legacy limiter numeric semantics as warnings, retaining operator values", () => {
    expect(rateSummary({type:"rate",max:100,interval:"10s",weight:50}).effectivePerSecond).toBe(10);
    expect(rateSummary({type:"rate",max:10,interval:"500ms",weight:150})).toMatchObject({effectivePerSecond:10,weight:100});
    expect(rateSummary({type:"rate",max:0,interval:"0s",weight:-1})).toMatchObject({effectivePerSecond:0,weight:0});
    expect(rateSummary({type:"rate",max:-2,interval:"1s"}).warning).toBeTruthy();
    expect(rateSummary({type:"inflight",max:0}).warning).toBeTruthy();
    expect(rateSummary({type:"inflight",max:2.5})).toMatchObject({effectiveCeiling:0});
    expect(rateSummary({type:"inflight",max:3})).toMatchObject({effectiveCeiling:3});
    expect(rateSummary({type:"rate",max:2.5,interval:"1s",weight:1.5})).toMatchObject({effectivePerSecond:0,weight:50});
    expect(rateSummary({interval:"nonsense"}).effectivePerSecond).toBeNull();
  });
});
