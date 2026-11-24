export type Point = [number, number];
export function alignedData(points: Point[]): [number[], (number | null)[]] {
  const ordered = points.filter((p) => Number.isFinite(p[0]) && Number.isFinite(p[1])).slice().sort((a, b) => a[0] - b[0]);
  return [ordered.map((p) => p[0]), ordered.map((p) => p[1])];
}
