import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Api } from './types';

const inTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

const real: Api = {
  listDrives: () => invoke('list_drives'),
  scanStart: (path) => invoke('scan_start', { path }),
  scanCancel: () => invoke('scan_cancel'),
  scanCurrent: () => invoke('scan_current'),
  scanChildren: (parts) => invoke('scan_children', { parts }),
  reveal: (parts) => invoke('reveal_in_explorer', { parts }),
  rulesList: () => invoke('rules_list'),
  planBuild: (ruleIds) => invoke('plan_build', { ruleIds }),
  planDiscard: () => invoke('plan_discard'),
  planExecute: (dryRun, recycle) => invoke('plan_execute', { dryRun, recycle }),
  cleanCancel: () => invoke('clean_cancel'),
  appStatus: () => invoke('app_status'),
  relaunchAsAdmin: () => invoke('relaunch_as_admin'),
  settingsGet: () => invoke('settings_get'),
  settingsSetExclusions: (exclusions) => invoke('settings_set_exclusions', { exclusions }),
  settingsSetCloud: (analyzeCloud, skipPaths) => invoke('settings_set_cloud', { analyzeCloud, skipPaths }),
  dupScan: (path, minSizeMb) => invoke('dup_scan', { path, minSizeMb }),
  dupCancel: () => invoke('dup_cancel'),
  dupCurrent: () => invoke('dup_current'),
  dupDelete: (selections, recycle) => invoke('dup_delete', { selections, recycle }),
  sysList: () => invoke('sys_list'),
  sysRun: (id) => invoke('sys_run', { id }),
  migPreflight: (source, target) => invoke('mig_preflight', { source, target }),
  migBlockers: (dir) => invoke('mig_blockers', { dir }),
  migStop: (pids, includeRelated, force) => invoke('mig_stop', { pids, includeRelated, force }),
  migStart: (source, target) => invoke('mig_start', { source, target }),
  migCancel: () => invoke('mig_cancel'),
  migList: () => invoke('mig_list'),
  migRestore: (id) => invoke('mig_restore', { id }),
  onMigProgress: (cb) => listen<never>('mig-progress', (e) => cb(e.payload)),
  candResolve: (items) => invoke('cand_resolve', { items }),
  candDelete: (items, recycle) => invoke('cand_delete', { items, recycle }),
  appsList: (includeStore) => invoke('apps_list', { includeStore }),
  appUninstall: (id, silent) => invoke('app_uninstall', { id, silent }),
  appLeftovers: (id, forced) => invoke('app_leftovers', { id, forced }),
  appDeleteLeftovers: (selected, recycle) => invoke('app_delete_leftovers', { selected, recycle }),
  onDupProgress: (cb) => listen<never>('dup-progress', (e) => cb(e.payload)),
  onScanProgress: (cb) => listen<never>('scan-progress', (e) => cb(e.payload)),
  onCleanProgress: (cb) => listen<never>('clean-progress', (e) => cb(e.payload)),
};

// 浏览器里单独预览界面（`npm run dev`）时使用模拟数据；发布版永远走真实后端。
export const api: Api =
  inTauri || !import.meta.env.DEV ? real : (await import('./mock')).mockApi;
