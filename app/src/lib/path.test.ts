import { describe, expect, it } from 'vitest';
import { breakableName, breakablePath, relParts, splitPath } from './path';

describe('splitPath', () => {
  it('separates the directory from the file name', () => {
    expect(splitPath('C:\\Users\\alice\\Videos\\holiday-2025.mp4')).toEqual({ dir: 'C:\\Users\\alice\\Videos', name: 'holiday-2025.mp4' });
    expect(splitPath('/home/a/b.txt')).toEqual({ dir: '/home/a', name: 'b.txt' });
  });

  it('keeps the drive root for files directly under it', () => {
    expect(splitPath('C:\\pagefile.sys')).toEqual({ dir: 'C:\\', name: 'pagefile.sys' });
  });

  it('handles trailing separators and bare names', () => {
    expect(splitPath('C:\\a\\b\\')).toEqual({ dir: 'C:\\a', name: 'b' });
    expect(splitPath('file.txt')).toEqual({ dir: '', name: 'file.txt' });
    expect(splitPath('')).toEqual({ dir: '', name: '' });
  });

  it('copes with very long paths without losing either part', () => {
    const dir = 'D:\\' + Array.from({ length: 30 }, (_, i) => `folder-${i}`).join('\\');
    const r = splitPath(`${dir}\\a-very-long-file-name-that-would-be-cut-off.vhdx`);
    expect(r.dir).toBe(dir);
    expect(r.name).toBe('a-very-long-file-name-that-would-be-cut-off.vhdx');
  });
});

describe('relParts', () => {
  it('returns the components below the scan root', () => {
    expect(relParts('C:\\', 'C:\\Users\\a\\x.bin')).toEqual(['Users', 'a', 'x.bin']);
    expect(relParts('C:\\Users', 'C:\\Users\\a\\x.bin')).toEqual(['a', 'x.bin']);
    expect(relParts('c:/users/', 'C:\\USERS\\a')).toEqual(['a']);
  });

  it('rejects the root itself and paths outside it', () => {
    expect(relParts('C:\\Users', 'C:\\Users')).toBeNull();
    expect(relParts('C:\\Users', 'C:\\Usersx\\a')).toBeNull();
    expect(relParts('C:\\Users', 'D:\\Users\\a')).toBeNull();
  });
});

describe('breakable display helpers', () => {
  it('add break opportunities without changing the visible text', () => {
    const strip = (x: string) => x.replace(/\u200b/g, '');
    expect(strip(breakablePath('C:\\Users\\alice\\Videos'))).toBe('C:\\Users\\alice\\Videos');
    expect(breakablePath('C:\\a\\b')).toBe('C:\\\u200ba\\\u200bb');
    expect(strip(breakableName('VID_2024-08.original.mp4'))).toBe('VID_2024-08.original.mp4');
    expect(breakableName('a_b')).toBe('a_\u200bb');
    expect(breakablePath('')).toBe('');
  });
});
