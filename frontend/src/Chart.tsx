import { useEffect, useMemo, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { alignedData, type Point } from "./chart-data";

interface ChartProps {
  points: Point[];
  color?: string;
  height?: number;
  label: string;
  unit?: string;
  threshold?: number;
}

export function Chart({ points, color = "#a4e4b5", height = 220, label, unit = "%", threshold }: ChartProps) {
  const element = useRef<HTMLDivElement>(null);
  const normalized = useMemo(() => alignedData(points), [points]);

  useEffect(() => {
    const root = element.current;
    if (!root || normalized[0].length === 0) return;
    const width = Math.max(240, root.clientWidth);
    const plot = new uPlot({
      width,
      height,
      padding: [10, 8, 0, 0],
      legend: { show: false },
      cursor: { drag: { x: false, y: false, setScale: false } },
      scales: { x: { time: true }, y: { auto: true, range: (_u, min, max) => {
        if (!Number.isFinite(min) || !Number.isFinite(max)) return [0, 1];
        const extra = Math.max((max - min) * 0.12, Math.abs(max) * 0.025, unit === "%" ? 2 : 0.1);
        return [Math.max(0, min - extra), max + extra];
      } } },
      axes: [
        { stroke: "#78837d", grid: { show: false }, ticks: { show: false }, font: "10px ui-monospace, monospace", size: 28 },
        { stroke: "#78837d", grid: { stroke: "rgba(150, 170, 158, .12)", width: 1 }, ticks: { stroke: "rgba(150, 170, 158, .2)", width: 1 }, font: "10px ui-monospace, monospace", size: 42,
          values: (_u, vals) => vals.map((v) => `${Number(v).toFixed(unit === "%" ? 0 : 1)}${unit}`) },
      ],
      series: [
        {},
        { label, stroke: color, width: 1.8, points: { show: false }, fill: "rgba(164, 228, 181, .06)" },
      ],
      hooks: threshold == null ? {} : { draw: [(u) => {
        const y = u.valToPos(threshold, "y", true);
        if (!Number.isFinite(y)) return;
        const ctx = u.ctx;
        ctx.save(); ctx.setLineDash([4, 4]); ctx.strokeStyle = "rgba(235, 176, 102, .7)";
        ctx.beginPath(); ctx.moveTo(u.bbox.left, y); ctx.lineTo(u.bbox.left + u.bbox.width, y); ctx.stroke(); ctx.restore();
      }] },
    }, normalized as uPlot.AlignedData, root);
    const observer = new ResizeObserver(() => {
      if (element.current) plot.setSize({ width: Math.max(240, element.current.clientWidth), height });
    });
    observer.observe(root);
    return () => { observer.disconnect(); plot.destroy(); };
  }, [normalized, color, height, label, unit, threshold]);

  return <div className="chart-frame" aria-label={`${label} historical chart`} role="img"><div ref={element} className="chart-host" /></div>;
}
