import { describe, expect, it } from 'vitest';
import { cleanPath, driveOf, parseSpace, suggestTarget } from './migrate';

describe('cleanPath', () => {
  it('normalizes separators, prefixes and trailing slashes', () => {
    expect(cleanPath('  C:/Users/a/ ')).toBe('C:\\Users\\a');
    expect(cleanPath('\\\\?\\C:\\Foo\\')).toBe('C:\\Foo');
  });
});

describe('suggestTarget', () => {
  it('mirrors the source path under a dedicated folder on the target drive', () => {
    expect(suggestTarget('C:\\Users\\alice\\AppData\\Local\\Docker', 'D:\\')).toBe(
      'D:\\DiskClean-Migrated\\Users\\alice\\AppData\\Local\\Docker',
    );
    expect(suggestTarget('c:/Program Files/Foo/', 'e:')).toBe('E:\\DiskClean-Migrated\\Program Files\\Foo');
  });

  it('keeps same-named folders from different places apart', () => {
    expect(suggestTarget('C:\\a\\Cache', 'D:\\')).not.toBe(suggestTarget('C:\\b\\Cache', 'D:\\'));
  });

  it('returns an empty string for unusable input', () => {
    expect(suggestTarget('relative\\path', 'D:\\')).toBe('');
    expect(suggestTarget('\\\\server\\share\\x', 'D:\\')).toBe('');
    expect(suggestTarget('C:\\', 'D:\\')).toBe('');
    expect(suggestTarget('C:\\x', 'not a drive')).toBe('');
    expect(suggestTarget('', '')).toBe('');
  });
});

describe('driveOf / parseSpace', () => {
  it('extracts the drive letter', () => {
    expect(driveOf('d:\\x')).toBe('D');
    expect(driveOf('\\\\?\\E:\\x')).toBe('E');
    expect(driveOf('/tmp')).toBeNull();
  });

  it('parses the need/have detail', () => {
    expect(parseSpace('1000/10')).toEqual({ need: 1000, have: 10 });
    expect(parseSpace('x')).toBeNull();
    expect(parseSpace(null)).toBeNull();
  });
});
