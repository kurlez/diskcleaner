/** 文件/目录类型 → 图标种类。纯函数，便于测试。 */

export type IconKind =
  | 'folder' | 'file' | 'image' | 'video' | 'audio' | 'archive' | 'disk' | 'exe' | 'pdf'
  | 'doc' | 'sheet' | 'slide' | 'code' | 'db' | 'log' | 'text' | 'font' | 'config' | 'link'
  | 'regkey' | 'regvalue';

const GROUPS: Record<Exclude<IconKind, 'folder' | 'file' | 'regkey' | 'regvalue'>, string> = {
  image: 'png jpg jpeg gif bmp webp svg ico tif tiff heic heif raw psd avif',
  video: 'mp4 mkv avi mov wmv flv webm m4v mpg mpeg 3gp',
  audio: 'mp3 wav flac aac ogg m4a wma opus aiff',
  archive: 'zip rar 7z tar gz tgz bz2 xz zst lz4 cab z lzma',
  disk: 'vhd vhdx vmdk vdi iso img wim esd qcow2 dmg',
  exe: 'exe msi dll sys bat cmd com scr ocx msix drv cpl',
  pdf: 'pdf',
  doc: 'doc docx rtf odt pages',
  sheet: 'xls xlsx xlsm csv ods numbers',
  slide: 'ppt pptx odp key',
  code: 'js mjs cjs ts jsx tsx rs py java c cc cpp h hpp cs go rb php swift kt html htm css scss less ps1 sh lua svelte vue dart scala',
  db: 'db sqlite sqlite3 mdb accdb sql ldb mdf ndf ldf',
  log: 'log etl evtx',
  text: 'txt md markdown rst nfo',
  font: 'ttf otf woff woff2 fon',
  config: 'json xml yml yaml toml ini cfg conf config reg plist lock env gitignore gitattributes editorconfig',
  link: 'lnk url',
};

const BY_EXT: Map<string, IconKind> = new Map();
for (const [kind, exts] of Object.entries(GROUPS)) {
  for (const e of exts.split(' ')) BY_EXT.set(e, kind as IconKind);
}

const BY_NAME: Record<string, IconKind> = {
  dockerfile: 'code',
  makefile: 'code',
  cmakelists: 'code',
  license: 'text',
  readme: 'text',
};

export function iconKind(name: string, isDir: boolean): IconKind {
  if (isDir) return 'folder';
  const lower = name.toLowerCase();
  const special = BY_NAME[lower];
  if (special) return special;
  const dot = lower.lastIndexOf('.');
  if (dot < 0 || dot === lower.length - 1) return 'file';
  // `.gitignore` 这类点开头的文件，点后面的部分就是"扩展名"。
  const ext = lower.slice(dot + 1);
  return BY_EXT.get(ext) ?? 'file';
}
