/**
 * Squarified treemap（Bruls、Huizing、van Wijk）。
 * 把一组带权重的条目铺满一个矩形，面积与权重成正比，并尽量让每块接近正方形。
 */

export interface Rect { x: number; y: number; w: number; h: number }
export interface Item<T> { value: number; data: T }
export interface Tile<T> { rect: Rect; data: T; value: number }

/** 一行里最差的长宽比；越接近 1 越好。 */
function worst(row: number[], side: number): number {
  const sum = row.reduce((a, b) => a + b, 0);
  const max = Math.max(...row);
  const min = Math.min(...row);
  const s2 = side * side;
  return Math.max((s2 * max) / (sum * sum), (sum * sum) / (s2 * min));
}

export function squarify<T>(items: Item<T>[], rect: Rect): Tile<T>[] {
  const list = items.filter((i) => i.value > 0 && Number.isFinite(i.value)).sort((a, b) => b.value - a.value);
  const total = list.reduce((a, i) => a + i.value, 0);
  if (!list.length || total <= 0 || rect.w <= 0 || rect.h <= 0) return [];

  const scale = (rect.w * rect.h) / total;
  const areas = list.map((i) => i.value * scale);
  const tiles: Tile<T>[] = [];
  let { x, y, w, h } = rect;
  let i = 0;

  while (i < list.length) {
    const side = Math.min(w, h);
    let end = i + 1;
    let row = areas.slice(i, end);
    while (end < list.length) {
      const next = [...row, areas[end]];
      if (worst(next, side) > worst(row, side)) break;
      row = next;
      end++;
    }

    const rowSum = row.reduce((a, b) => a + b, 0);
    // 在较短边上沿着排一行：行厚度 = 面积和 / 边长。
    if (w >= h) {
      const rw = rowSum / h;
      let cy = y;
      row.forEach((a, k) => {
        const rh = a / rw;
        tiles.push({ rect: { x, y: cy, w: rw, h: rh }, data: list[i + k].data, value: list[i + k].value });
        cy += rh;
      });
      x += rw;
      w -= rw;
    } else {
      const rh = rowSum / w;
      let cx = x;
      row.forEach((a, k) => {
        const rw = a / rh;
        tiles.push({ rect: { x: cx, y, w: rw, h: rh }, data: list[i + k].data, value: list[i + k].value });
        cx += rw;
      });
      y += rh;
      h -= rh;
    }
    i = end;
  }
  return tiles;
}

/**
 * 把太小、看不清的条目合并成一个"其他"。
 * 只保留最大的 `max` 项，且每项至少占总量的 `minFraction`。
 */
export function groupSmall<T>(
  items: Item<T>[],
  max: number,
  minFraction: number,
): { kept: Item<T>[]; otherCount: number; otherValue: number } {
  const sorted = items.filter((i) => i.value > 0).sort((a, b) => b.value - a.value);
  const total = sorted.reduce((a, i) => a + i.value, 0);
  const kept: Item<T>[] = [];
  let otherValue = 0;
  let otherCount = 0;
  for (const it of sorted) {
    if (kept.length < max && it.value >= total * minFraction) kept.push(it);
    else {
      otherValue += it.value;
      otherCount++;
    }
  }
  return { kept, otherCount, otherValue };
}

/** 名称 → 稳定的色相（0–359），同名目录始终同色。 */
export function hueOf(name: string): number {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return h % 360;
}
