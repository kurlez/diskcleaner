import { describe, expect, it } from 'vitest';
import { analyze, isInside, keyOf, type Candidate } from './candidates';

const c = (parts: string[], size: number, is_dir = true, files = 1): Candidate => ({
  key: keyOf(parts), parts, name: parts[parts.length - 1], size, is_dir, file_count: files,
});

describe('isInside', () => {
  it('is true only for strict descendants', () => {
    expect(isInside(['a', 'b'], ['a'])).toBe(true);
    expect(isInside(['a', 'b', 'c'], ['a'])).toBe(true);
    expect(isInside(['a'], ['a'])).toBe(false);
    expect(isInside(['a'], ['a', 'b'])).toBe(false);
    expect(isInside(['ab', 'c'], ['a'])).toBe(false);
    expect(isInside(['x', 'b'], ['a'])).toBe(false);
  });
});

describe('analyze', () => {
  it('counts nested candidates only once', () => {
    const items = [c(['junk'], 550, true, 2), c(['junk', 'big.bin'], 500, false), c(['junk', 'sub', 'x'], 50, false), c(['keep', 'a'], 10, false)];
    const a = analyze(items);
    expect(a.effective.map((x) => x.key)).toEqual([keyOf(['junk']), keyOf(['keep', 'a'])]);
    expect([...a.covered].sort()).toEqual([keyOf(['junk', 'big.bin']), keyOf(['junk', 'sub', 'x'])].sort());
    expect(a.totalSize).toBe(560);
    expect(a.totalFiles).toBe(3);
  });

  it('does not treat siblings with a common name prefix as nested', () => {
    const a = analyze([c(['a'], 1), c(['ab'], 2)]);
    expect(a.covered.size).toBe(0);
    expect(a.totalSize).toBe(3);
  });

  it('handles the empty list', () => {
    expect(analyze([])).toEqual({ effective: [], covered: new Set(), totalSize: 0, totalFiles: 0 });
  });
});
