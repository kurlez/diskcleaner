import { describe, expect, it } from 'vitest';
import { iconKind } from './fileicon';

describe('iconKind', () => {
  it('uses the folder icon for directories regardless of the name', () => {
    expect(iconKind('Documents', true)).toBe('folder');
    expect(iconKind('archive.zip', true)).toBe('folder');
  });

  it('maps common extensions', () => {
    const cases: [string, string][] = [
      ['rootfs.vhdx', 'disk'], ['rootfs.vhdx.zst', 'archive'], ['photo.JPG', 'image'],
      ['movie.mkv', 'video'], ['song.flac', 'audio'], ['setup.exe', 'exe'], ['x.dll', 'exe'],
      ['report.pdf', 'pdf'], ['a.docx', 'doc'], ['b.xlsx', 'sheet'], ['c.pptx', 'slide'],
      ['main.rs', 'code'], ['app.svelte', 'code'], ['data.sqlite3', 'db'], ['system.evtx', 'log'],
      ['notes.md', 'text'], ['font.woff2', 'font'], ['package.json', 'config'], ['a.lnk', 'link'],
      ['ubuntu.iso', 'disk'], ['backup.tar.gz', 'archive'],
    ];
    for (const [name, kind] of cases) expect(iconKind(name, false), name).toBe(kind);
  });

  it('handles dotfiles, special names and unknown extensions', () => {
    expect(iconKind('.gitignore', false)).toBe('config');
    expect(iconKind('Dockerfile', false)).toBe('code');
    expect(iconKind('MAKEFILE', false)).toBe('code');
    expect(iconKind('.cowork-adopted', false)).toBe('file');
    expect(iconKind('vmlinuz', false)).toBe('file');
    expect(iconKind('weird.zzz', false)).toBe('file');
    expect(iconKind('trailingdot.', false)).toBe('file');
    expect(iconKind('', false)).toBe('file');
  });
});
