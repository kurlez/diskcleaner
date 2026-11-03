/** 目录迁移页的纯逻辑：建议的目标路径、解析预检返回的详情。 */

/** 去掉 `\\?\` 前缀与末尾分隔符，统一成反斜杠。 */
export function cleanPath(p: string): string {
  return p.trim().replace(/^\\\\\?\\/, '').replace(/\//g, '\\').replace(/\\+$/, '');
}

/**
 * 由源目录和目标盘建议一个目标路径：`<盘>\DiskClean-Migrated\<源路径去掉盘符>`。
 * 保留完整的相对路径，所以来自不同位置的同名目录（如两个 `Cache`）不会冲突。
 * 源不是带盘符的路径（相对路径、UNC）或目标盘无效时返回空串。
 */
export function suggestTarget(source: string, driveMount: string): string {
  const src = cleanPath(source);
  const m = /^([A-Za-z]):\\(.+)$/.exec(src);
  const d = /^([A-Za-z]):/.exec(driveMount.trim());
  if (!m || !d) return '';
  return `${d[1].toUpperCase()}:\\DiskClean-Migrated\\${m[2]}`;
}

/** 盘符（大写），不是带盘符的路径时返回 null。 */
export function driveOf(path: string): string | null {
  const m = /^([A-Za-z]):/.exec(cleanPath(path));
  return m ? m[1].toUpperCase() : null;
}

/** 预检的 `not_enough_space` 详情形如 `需要/可用`（字节）。 */
export function parseSpace(detail: string | null): { need: number; have: number } | null {
  const m = /^(\d+)\/(\d+)$/.exec(detail ?? '');
  return m ? { need: Number(m[1]), have: Number(m[2]) } : null;
}
