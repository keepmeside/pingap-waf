import { describe, expect, it } from "vitest";
import { safeEventUri } from "@/helpers/event-uri";

describe("safeEventUri", () => {
  it("removes query values from event display", () => {
    expect(safeEventUri("/login?token=secret&password=hunter2")).toBe("/login");
  });

  it("keeps paths and handles missing URIs", () => {
    expect(safeEventUri("/health")).toBe("/health");
    expect(safeEventUri(undefined)).toBe("URI not captured");
  });
});
