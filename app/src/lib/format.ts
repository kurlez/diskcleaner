const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** 1024 进制，与后端 `format_size` 保持一致。 */
export function formatSize(bytes: number): string {
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${bytes} B` : `${v.toFixed(1)} ${UNITS[i]}`;
}

/** 占比（0–100），分母为 0 时返回 0。 */
export function percent(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.min(100, Math.max(0, (part / whole) * 100));
}

/** 路径分量：把目录名序列拼回展示路径的最后一段。 */
export function joinPath(root: string, parts: string[]): string {
  const sep = root.includes('\\') ? '\\' : '/';
  const base = root.endsWith(sep) ? root.slice(0, -1) : root;
  return [base, ...parts].join(sep);
}
