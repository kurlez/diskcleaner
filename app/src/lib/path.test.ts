import { describe, expect, it } from 'vitest';
import { nameSegments, pathSegments, relParts, splitPath } from './path';

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

describe('unicode paths', () => {
  it('splits Chinese, Japanese, Korean and emoji paths without damaging them', () => {
    expect(splitPath('D:\\资料库\\二级目录 📁\\公司年度总结（未剪辑）📹.mp4')).toEqual({
      dir: 'D:\\资料库\\二级目录 📁',
      name: '公司年度总结（未剪辑）📹.mp4',
    });
    expect(splitPath('C:\\ユーザー\\한국어.txt')).toEqual({ dir: 'C:\\ユーザー', name: '한국어.txt' });
    expect(relParts('D:\\资料库', 'd:\\资料库\\二级目录 📁\\日本語.txt')).toEqual(['二级目录 📁', '日本語.txt']);
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

describe('display segments', () => {
  it('split after separators and join back to exactly the original text', () => {
    for (const path of ['C:\\Users\\alice\\Videos', 'D:\\', '/home/a/b', 'plain', '', '\\\\?\\C:\\x\\', 'D:\\项目\\报告📄 终稿\\']) {
      expect(pathSegments(path).join('')).toBe(path);
    }
    expect(pathSegments('C:\\a\\b')).toEqual(['C:\\', 'a\\', 'b']);
  });

  it('never inserts invisible characters', () => {
    const joined = pathSegments('C:\\Users\\alice\\Videos').join('') + nameSegments('a_b-c.d').join('');
    expect(/[\u200b\u200c\u200d\ufeff\u00ad]/.test(joined)).toBe(false);
  });

  it('splits file names after _ - and . and rejoins losslessly', () => {
    expect(nameSegments('pagefile.sys')).toEqual(['pagefile.', 'sys']);
    for (const n of ['VID_2024-08.original.mp4', '微信图片_20240815.jpg', '📄 notes-v2.txt', 'noext', '']) {
      expect(nameSegments(n).join('')).toBe(n);
    }
  });
});
