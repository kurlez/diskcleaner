export interface PieInput { name: string; size: number; is_dir: boolean }
export interface Slice {
  /** 对应的子项；`null` 表示"其他"（排名靠后的项目与小于最小显示大小的项目）。 */
  item: PieInput | null;
  /** 该切片包含的项目数（其他：排名靠后的个数，不含被折叠的小文件）。 */
  count: number;
  size: number;
  fraction: number;
  start: number;
  end: number;
}

/** 取最大的 `max` 项，其余连同被折叠的小项目（`smallSize`）合成一个"其他"切片。角度以弧度计，自 12 点方向顺时针。 */
export function pieSlices(items: PieInput[], smallSize: number, max = 8): Slice[] {
  const sorted = items.filter((i) => i.size > 0).sort((a, b) => b.size - a.size);
  const top = sorted.slice(0, max);
  const rest = sorted.slice(max);
  const otherSize = rest.reduce((a, i) => a + i.size, 0) + Math.max(0, smallSize);
  const total = top.reduce((a, i) => a + i.size, 0) + otherSize;
  if (total <= 0) return [];
  const out: Slice[] = [];
  let angle = 0;
  const push = (item: PieInput | null, size: number, count: number) => {
    const fraction = size / total;
    out.push({ item, count, size, fraction, start: angle, end: angle + fraction * Math.PI * 2 });
    angle += fraction * Math.PI * 2;
  };
  for (const i of top) push(i, i.size, 1);
  if (otherSize > 0) push(null, otherSize, rest.length);
  return out;
}

/** 圆环切片的 SVG 路径。整圆（只有一个切片）拆成两段半圆，避免起止点重合时不绘制。 */
export function arcPath(cx: number, cy: number, r: number, ri: number, a0: number, a1: number): string {
  const full = a1 - a0 >= Math.PI * 2 - 1e-9;
  const end = full ? a0 + Math.PI * 2 - 1e-4 : a1;
  const pt = (rad: number, rr: number) => `${(cx + rr * Math.sin(rad)).toFixed(2)} ${(cy - rr * Math.cos(rad)).toFixed(2)}`;
  const large = end - a0 > Math.PI ? 1 : 0;
  return `M ${pt(a0, r)} A ${r} ${r} 0 ${large} 1 ${pt(end, r)} L ${pt(end, ri)} A ${ri} ${ri} 0 ${large} 0 ${pt(a0, ri)} Z`;
}
