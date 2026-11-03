/** 候选清单的纯逻辑（不依赖界面）：去重、包含关系、合计。 */

export interface Candidate {
  /** 扫描树里的路径分量拼成的稳定键。 */
  key: string;
  parts: string[];
  name: string;
  size: number;
  is_dir: boolean;
  file_count: number;
}

export const keyOf = (parts: string[]): string => parts.join('\u0000');

/** `child` 是否位于 `parent` 之内（不含相等）。 */
export function isInside(child: string[], parent: string[]): boolean {
  return parent.length < child.length && parent.every((p, i) => child[i] === p);
}

export interface Analysis {
  /** 真正会被处理的项：没有被其他候选包含。 */
  effective: Candidate[];
  /** 被包含在另一个候选里的项的键（不会单独处理，也不重复计入合计）。 */
  covered: Set<string>;
  totalSize: number;
  totalFiles: number;
}

export function analyze(items: Candidate[]): Analysis {
  const covered = new Set<string>();
  for (const c of items) {
    if (items.some((o) => o.key !== c.key && isInside(c.parts, o.parts))) covered.add(c.key);
  }
  const effective = items.filter((c) => !covered.has(c.key));
  return {
    effective,
    covered,
    totalSize: effective.reduce((a, c) => a + c.size, 0),
    totalFiles: effective.reduce((a, c) => a + c.file_count, 0),
  };
}
