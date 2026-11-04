import { describe, expect, it } from 'vitest';
import { arcPath, pieSlices } from './pie';

const f = (name: string, size: number) => ({ name, size, is_dir: false });

describe('pieSlices', () => {
  it('orders by size, folds the tail and small items into one "other" slice', () => {
    const items = [f('a', 10), f('b', 50), f('c', 30), f('d', 5), f('e', 4)];
    const s = pieSlices(items, 1, 3);
    expect(s.map((x) => x.item?.name ?? null)).toEqual(['b', 'c', 'a', null]);
    expect(s[3].size).toBe(10); // d + e + small
    expect(s[3].count).toBe(2);
    expect(s.reduce((a, x) => a + x.fraction, 0)).toBeCloseTo(1);
    expect(s[s.length - 1].end).toBeCloseTo(Math.PI * 2);
    expect(s[1].start).toBeCloseTo(s[0].end);
  });

  it('shows only small items as one other slice and ignores empty entries', () => {
    const s = pieSlices([f('z', 0)], 400);
    expect(s).toHaveLength(1);
    expect(s[0].item).toBeNull();
    expect(pieSlices([], 0)).toEqual([]);
  });
});

describe('arcPath', () => {
  it('draws a closed ring segment, also for a full circle', () => {
    expect(arcPath(100, 100, 80, 50, 0, Math.PI / 2)).toMatch(/^M .* A 80 80 0 0 1 .* L .* A 50 50 0 0 0 .* Z$/);
    expect(arcPath(100, 100, 80, 50, 0, Math.PI * 2)).toContain(' 1 1 ');
  });
});
