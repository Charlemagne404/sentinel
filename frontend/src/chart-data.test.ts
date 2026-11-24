import { describe, expect, it } from "vitest";
import { alignedData } from "./chart-data";

describe("alignedData", () => {
  it("filters invalid values and sorts samples by time without mutating the input", () => {
    const points: [number, number][] = [[30, 3], [10, 1], [20, Number.NaN], [40, 4]];
    expect(alignedData(points)).toEqual([[10, 30, 40], [1, 3, 4]]);
    expect(points[0]).toEqual([30, 3]);
  });

  it("returns aligned empty arrays", () => {
    expect(alignedData([])).toEqual([[], []]);
  });
});
