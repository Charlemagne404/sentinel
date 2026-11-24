import { describe, expect, it } from "vitest";
import { alignedData } from "./chart-data";

describe("alignedData", () => {
  it("filters invalid values and sorts samples by time without mutating the input", () => {
    const points: [number, number][] = [[30, 3], [10, 1], [20, Number.NaN], [40, 4]];
    expect(alignedData(points)).toEqual([[10, 20, 30, 40], [1, null, 3, 4]]);
    expect(points[0]).toEqual([30, 3]);
  });

  it("inserts an explicit gap when one or more sampling intervals are missing", () => {
    expect(alignedData([[0, 1], [10, 2], [30, 4], [40, 5]])).toEqual([
      [0, 10, 20, 30, 40], [1, 2, null, 4, 5],
    ]);
  });

  it("returns aligned empty arrays", () => {
    expect(alignedData([])).toEqual([[], []]);
  });
});
