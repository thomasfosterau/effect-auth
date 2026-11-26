import { describe, expect, it } from "vite-plus/test";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Arr from "effect/Array";
import { amortizedPrune } from "./AmortizedPrune.ts";

describe("amortizedPrune", () => {
  it("prunes only once the map reaches its floor, then once it has doubled again", () => {
    const map = MutableHashMap.empty<number, boolean>();
    const prune = amortizedPrune(map, 4);
    let scans = 0;
    const isStale = (stale: boolean) => {
      scans++;
      return stale;
    };
    Arr.forEach(Arr.range(0, 2), (i) => MutableHashMap.set(map, i, true));
    prune(isStale);
    expect(scans).toBe(0);
    MutableHashMap.set(map, 3, false);
    prune(isStale);
    // Three stale entries went; the live one stays.
    expect(MutableHashMap.size(map)).toBe(1);
    expect(scans).toBe(4);
    // Next prune waits for the floor again (max(4, 1 * 2)).
    Arr.forEach(Arr.range(10, 11), (i) => MutableHashMap.set(map, i, false));
    prune(isStale);
    expect(scans).toBe(4);
    MutableHashMap.set(map, 12, false);
    prune(isStale);
    expect(scans).toBe(8);
    expect(MutableHashMap.size(map)).toBe(4);
  });
});
