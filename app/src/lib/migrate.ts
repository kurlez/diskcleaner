/** 目录迁移页的纯逻辑：建议的目标路径、解析预检返回的详情。 */

const isPosix = (p: string) => p.trim().startsWith('/');

/** Windows：去掉 `\\?\` 前缀与末尾分隔符，统一成反斜杠；macOS 路径只去掉末尾的 `/`。 */
export function cleanPath(p: string): string {
  const t = p.trim();
  if (isPosix(t)) return t.length > 1 ? t.replace(/\/+$/, '') : t;
  return t.replace(/^\\\\\?\\/, '').replace(/\//g, '\\').replace(/\\+$/, '');
}

/** macOS：路径所在的卷。`/Volumes/<名称>/...` 属于那块外置卷，其余都在启动卷 `/`。 */
function posixVolume(path: string): { mount: string; rest: string } {
  const m = /^\/Volumes\/([^/]+)(?:\/(.*))?$/.exec(path);
  return m ? { mount: `/Volumes/${m[1]}`, rest: m[2] ?? '' } : { mount: '/', rest: path.replace(/^\/+/, '') };
}

/**
 * 由源目录和目标盘建议一个目标路径：`<盘>/DiskClean-Migrated/<源路径去掉盘符或卷>`。
 * 保留完整的相对路径，所以来自不同位置的同名目录（如两个 `Cache`）不会冲突。
 * 源不是完整路径（相对路径、UNC）或目标盘无效时返回空串。
 */
export function suggestTarget(source: string, driveMount: string): string {
  const src = cleanPath(source);
  if (isPosix(src)) {
    const mount = driveMount.trim();
    if (!isPosix(mount)) return '';
    const { rest } = posixVolume(src);
    if (!rest) return '';
    return `${mount.replace(/\/+$/, '')}/DiskClean-Migrated/${rest}`;
  }
  const m = /^([A-Za-z]):\\(.+)$/.exec(src);
  const d = /^([A-Za-z]):/.exec(driveMount.trim());
  if (!m || !d) return '';
  return `${d[1].toUpperCase()}:\\DiskClean-Migrated\\${m[2]}`;
}

/** 盘符（大写）；macOS 返回卷的挂载点（`/` 或 `/Volumes/名称`）；都不是时返回 null。 */
export function driveOf(path: string): string | null {
  const c = cleanPath(path);
  if (isPosix(c)) return posixVolume(c).mount;
  const m = /^([A-Za-z]):/.exec(c);
  return m ? m[1].toUpperCase() : null;
}

/** 预检的 `not_enough_space` 详情形如 `需要/可用`（字节）。 */
export function parseSpace(detail: string | null): { need: number; have: number } | null {
  const m = /^(\d+)\/(\d+)$/.exec(detail ?? '');
  return m ? { need: Number(m[1]), have: Number(m[2]) } : null;
}
