export type View = 'dashboard' | 'scan' | 'duplicates' | 'uninstall' | 'migrate' | 'clean' | 'settings';

/** 跨页面共享的导航状态。`scanRequest` 每增加一次，分析页就用 `scanPath` 自动开始扫描。 */
export const nav = $state<{ view: View; scanPath: string; scanRequest: number; migrateSource: string; migrateRequest: number }>({
  view: 'dashboard',
  scanPath: 'C:\\',
  scanRequest: 0,
  migrateSource: '',
  migrateRequest: 0,
});

/** 转到"目录迁移"页并预填源目录。 */
export function goMigrate(path: string) {
  nav.migrateSource = path;
  nav.migrateRequest++;
  nav.view = 'migrate';
}

export function goScan(path: string) {
  nav.scanPath = path;
  nav.scanRequest++;
  nav.view = 'scan';
}
