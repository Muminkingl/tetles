import { describe, expect, it } from "vitest";
import { buildAttackScenarios } from "../src/attacker-simulator.js";

describe("attacker simulator", () => {
  it("rejects copied-token, replay, method, URL, and stale-proof attacks", async () => {
    const scenarios = await buildAttackScenarios();

    for (const scenario of scenarios) {
      const result = await scenario.run();
      expect(result, scenario.name).toEqual({
        ok: false,
        reasonCode: scenario.expectedReason,
      });
    }
  });
});
