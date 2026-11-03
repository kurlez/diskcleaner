/** 路径显示与处理的纯函数（同时兼容 `\` 与 `/`）。 */

/** 把路径拆成所在目录与文件名。根目录下的文件，目录保留盘符根（如 `C:\`）。 */
export function splitPath(path: string): { dir: string; name: string } {
  const p = path.replace(/[\\/]+$/, '');
  const i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
  if (i < 0) return { dir: '', name: p };
  const dir = p.slice(0, i);
  // `C:` 后面补回分隔符，显示为 `C:\`。
  return { dir: /^[A-Za-z]:$/.test(dir) ? `${dir}\\` : dir, name: p.slice(i + 1) };
}

/**
 * `path` 相对扫描根 `root` 的目录名序列（扫描树里的路径分量）。
 * 不在根之内（或就是根本身）返回 null。比较不区分大小写。
 */
export function relParts(root: string, path: string): string[] | null {
  const norm = (s: string) => s.replace(/[\\/]+/g, '\\').replace(/\\$/, '');
  const r = norm(root);
  const p = norm(path);
  if (p.toLowerCase() === r.toLowerCase() || !p.toLowerCase().startsWith(`${r.toLowerCase()}\\`)) return null;
  return p.slice(r.length + 1).split('\\').filter(Boolean);
}

/**
 * 把路径拆成若干段，每段以分隔符结尾，用来在两段之间放 `<wbr>`：
 * 让很长的路径优先在目录边界换行，而不是在单词中间断开。
 * 只在显示时使用，**不往文字里插入任何字符**，所以选中复制出来的仍是原始文本。
 */
export function pathSegments(path: string): string[] {
  return path.match(/[^\\/]*[\\/]|[^\\/]+$/g) ?? [];
}

/** 文件名：在 `_`、`-`、`.` 之后提供换行机会。 */
export function nameSegments(name: string): string[] {
  return name.match(/[^_\-.]*[_\-.]|[^_\-.]+$/g) ?? [];
}
