import { keyOf, type Candidate } from './candidates';

/** 跨组件共享的候选清单。新的扫描会使旧的路径失效，所以扫描开始时要清空。 */
export const cands = $state<{ items: Candidate[]; open: boolean }>({ items: [], open: false });

export const hasCand = (parts: string[]): boolean => cands.items.some((c) => c.key === keyOf(parts));

export function toggleCand(c: Omit<Candidate, 'key'>) {
  const key = keyOf(c.parts);
  if (cands.items.some((x) => x.key === key)) cands.items = cands.items.filter((x) => x.key !== key);
  else cands.items = [...cands.items, { ...c, key }];
}

export function removeCand(key: string) {
  cands.items = cands.items.filter((c) => c.key !== key);
}

export function clearCands() {
  cands.items = [];
  cands.open = false;
}
