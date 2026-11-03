export type View = 'dashboard' | 'scan' | 'clean' | 'settings';

/** 跨页面共享的导航状态。`scanRequest` 每增加一次，分析页就用 `scanPath` 自动开始扫描。 */
export const nav = $state<{ view: View; scanPath: string; scanRequest: number }>({
  view: 'dashboard',
  scanPath: 'C:\\',
  scanRequest: 0,
});

export function goScan(path: string) {
  nav.scanPath = path;
  nav.scanRequest++;
  nav.view = 'scan';
}
