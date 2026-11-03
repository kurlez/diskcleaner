import { describe, expect, it } from 'vitest';
import { groupSmall, hueOf, squarify, type Rect } from './treemap';

const area = (r: Rect) => r.w * r.h;
const R: Rect = { x: 0, y: 0, w: 600, h: 400 };
const inside = (r: Rect, c: Rect) =>
  r.x >= c.x - 1e-6 && r.y >= c.y - 1e-6 && r.x + r.w <= c.x + c.w + 1e-6 && r.y + r.h <= c.y + c.h + 1e-6;
const overlap = (a: Rect, b: Rect) =>
  Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x) > 1e-6 &&
  Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y) > 1e-6;

describe('squarify', () => {
  const items = [6, 6, 4, 3, 2, 2, 1].map((v, i) => ({ value: v, data: `n${i}` }));

  it('fills the container exactly', () => {
    const tiles = squarify(items, R);
    expect(tiles).toHaveLength(items.length);
    expect(tiles.reduce((a, t) => a + area(t.rect), 0)).toBeCloseTo(area(R), 4);
  });

  it('gives each tile an area proportional to its value', () => {
    const total = items.reduce((a, i) => a + i.value, 0);
    for (const t of squarify(items, R)) expect(area(t.rect) / area(R)).toBeCloseTo(t.value / total, 6);
  });

  it('keeps tiles inside the container without overlaps', () => {
    const tiles = squarify(items, R);
    for (const t of tiles) expect(inside(t.rect, R)).toBe(true);
    for (let i = 0; i < tiles.length; i++)
      for (let j = i + 1; j < tiles.length; j++) expect(overlap(tiles[i].rect, tiles[j].rect)).toBe(false);
  });

  it('works with a non-zero origin and a tall container', () => {
    const c: Rect = { x: 50, y: 20, w: 100, h: 500 };
    const tiles = squarify(items, c);
    expect(tiles.reduce((a, t) => a + area(t.rect), 0)).toBeCloseTo(area(c), 4);
    for (const t of tiles) expect(inside(t.rect, c)).toBe(true);
  });

  it('produces reasonably square tiles', () => {
    const many = Array.from({ length: 40 }, (_, i) => ({ value: 40 - i, data: i }));
    const worstRatio = Math.max(
      ...squarify(many, R).map((t) => Math.max(t.rect.w / t.rect.h, t.rect.h / t.rect.w)),
    );
    expect(worstRatio).toBeLessThan(4);
  });

  it('orders tiles from largest to smallest', () => {
    const v = squarify(items, R).map((t) => t.value);
    expect(v).toEqual([...v].sort((a, b) => b - a));
  });

  it('handles degenerate input', () => {
    expect(squarify([], R)).toEqual([]);
    expect(squarify([{ value: 0, data: 1 }], R)).toEqual([]);
    expect(squarify([{ value: -5, data: 1 }, { value: NaN, data: 2 }], R)).toEqual([]);
    expect(squarify(items, { x: 0, y: 0, w: 0, h: 100 })).toEqual([]);
    const one = squarify([{ value: 7, data: 'a' }], R);
    expect(one).toHaveLength(1);
    for (const k of ['x', 'y', 'w', 'h'] as const) expect(one[0].rect[k]).toBeCloseTo(R[k], 6);
  });
});

describe('groupSmall', () => {
  const items = [100, 50, 5, 1, 1].map((v) => ({ value: v, data: v }));
  it('merges items below the threshold', () => {
    const g = groupSmall(items, 10, 0.02);
    expect(g.kept.map((i) => i.value)).toEqual([100, 50, 5]);
    expect(g.otherCount).toBe(2);
    expect(g.otherValue).toBe(2);
  });
  it('caps the number of kept items', () => {
    const g = groupSmall(items, 2, 0);
    expect(g.kept).toHaveLength(2);
    expect(g.otherCount).toBe(3);
    expect(g.otherValue).toBe(7);
  });
  it('ignores empty entries', () => {
    expect(groupSmall([{ value: 0, data: 0 }], 5, 0.1)).toEqual({ kept: [], otherCount: 0, otherValue: 0 });
  });
});

describe('hueOf', () => {
  it('is stable and in range', () => {
    expect(hueOf('Windows')).toBe(hueOf('Windows'));
    expect(hueOf('Windows')).not.toBe(hueOf('Users'));
    for (const n of ['', 'a', '文件', 'x'.repeat(500)]) {
      const h = hueOf(n);
      expect(h).toBeGreaterThanOrEqual(0);
      expect(h).toBeLessThan(360);
    }
  });
});
