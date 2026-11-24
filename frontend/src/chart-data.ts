export type Point = [number, number];
export function alignedData(points: Point[]): [number[], (number | null)[]] {
  const ordered = points.filter((p) => Number.isFinite(p[0]) && Number.isFinite(p[1])).slice().sort((a, b) => a[0] - b[0]);
  const intervals = ordered.slice(1)
    .map((point, index) => point[0] - ordered[index][0])
    .filter((interval) => interval > 0)
    .sort((a, b) => a - b);
  const typicalInterval = intervals.length ? intervals[Math.floor((intervals.length - 1) * 0.25)] : 0;
  const times: number[] = [];
  const values: (number | null)[] = [];
  let previous: Point | undefined;
  for (const point of ordered) {
    if (previous && typicalInterval > 0 && point[0] - previous[0] > typicalInterval * 1.75) {
      // A null is an explicit uPlot discontinuity. It prevents sparse samples
      // from being joined by a line that implies measurements were present.
      times.push(previous[0] + (point[0] - previous[0]) / 2);
      values.push(null);
    }
    times.push(point[0]);
    values.push(point[1]);
    previous = point;
  }
  return [times, values];
}
