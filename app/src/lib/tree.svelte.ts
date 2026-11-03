import { keyOf } from './candidates';

/**
 * 目录树的展开状态。放在组件之外，刷新时重新创建节点也不会把用户展开的目录收起来。
 * 开始新的扫描时清空（旧路径已经没有意义）。
 */
export const treeState = $state<{ expanded: Set<string> }>({ expanded: new Set() });

export const isExpanded = (parts: string[]): boolean => treeState.expanded.has(keyOf(parts));

export function setExpanded(parts: string[], open: boolean) {
  const next = new Set(treeState.expanded);
  if (open) next.add(keyOf(parts));
  else next.delete(keyOf(parts));
  treeState.expanded = next;
}

export function resetTree() {
  treeState.expanded = new Set();
}
