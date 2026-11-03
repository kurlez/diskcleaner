import { describe, expect, it } from 'vitest';
import { formatSize, joinPath, percent } from './format';

describe('formatSize', () => {
  it('matches the backend format', () => {
    expect(formatSize(0)).toBe('0 B');
    expect(formatSize(1023)).toBe('1023 B');
    expect(formatSize(1536)).toBe('1.5 KB');
    expect(formatSize(5 * 1024 ** 3)).toBe('5.0 GB');
    expect(formatSize(3 * 1024 ** 5)).toBe('3072.0 TB');
  });
});

describe('percent', () => {
  it('clamps and handles zero', () => {
    expect(percent(1, 0)).toBe(0);
    expect(percent(50, 200)).toBe(25);
    expect(percent(300, 200)).toBe(100);
    expect(percent(-5, 200)).toBe(0);
  });
});

describe('joinPath', () => {
  it('uses the separator of the root', () => {
    expect(joinPath('C:\\', ['Users', 'a'])).toBe('C:\\Users\\a');
    expect(joinPath('C:\\Data', ['x'])).toBe('C:\\Data\\x');
    expect(joinPath('/tmp', ['x'])).toBe('/tmp/x');
  });
});
