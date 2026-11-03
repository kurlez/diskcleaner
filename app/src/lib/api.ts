import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Api } from './types';

const inTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

const real: Api = {
  listDrives: () => invoke('list_drives'),
  scanStart: (path) => invoke('scan_start', { path }),
  scanCancel: () => invoke('scan_cancel'),
  scanChildren: (parts) => invoke('scan_children', { parts }),
  reveal: (parts) => invoke('reveal_in_explorer', { parts }),
  rulesList: () => invoke('rules_list'),
  planBuild: (ruleIds) => invoke('plan_build', { ruleIds }),
  planDiscard: () => invoke('plan_discard'),
  planExecute: (dryRun, recycle) => invoke('plan_execute', { dryRun, recycle }),
  cleanCancel: () => invoke('clean_cancel'),
  settingsGet: () => invoke('settings_get'),
  settingsSetExclusions: (exclusions) => invoke('settings_set_exclusions', { exclusions }),
  onScanProgress: (cb) => listen<never>('scan-progress', (e) => cb(e.payload)),
  onCleanProgress: (cb) => listen<never>('clean-progress', (e) => cb(e.payload)),
};

// 浏览器里单独预览界面（`npm run dev`）时使用模拟数据；发布版永远走真实后端。
export const api: Api =
  inTauri || !import.meta.env.DEV ? real : (await import('./mock')).mockApi;
