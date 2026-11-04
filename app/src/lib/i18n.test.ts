import { describe, expect, it } from 'vitest';
import { en } from './locales/en';
import { zh } from './locales/zh';

// 后端内置规则与错误码；新增规则/错误码时必须同步翻译。
const RULE_IDS = [
  'user_temp', 'system_temp', 'thumbnail_cache', 'crash_dumps', 'delivery_optimization',
  'old_logs', 'browser_cache', 'windows_update_cache', 'dev_caches',
];
const SKIP_REASONS = [
  'denied', 'reparse_point', 'cloud_placeholder', 'too_new', 'protected_inside', 'non_utf8', 'io',
];
// 扫描回退原因代码（后端 FastScanFn 返回）。
const FALLBACK_CODES = ['access_denied', 'not_ntfs', 'path_not_found', 'other'];
const LEFTOVER_REASONS = [
  'install_location', 'name_match', 'publisher_emptied', 'uninstall_entry', 'app_path',
  'auto_run', 'stale_service', 'com_registration', 'shortcut',
];
const MIG_ISSUES = [
  'invalid_path', 'source_missing', 'source_not_dir', 'source_is_link', 'already_migrated', 'cloud_location',
  'source_protected', 'target_protected', 'target_inside_source', 'source_inside_target',
  'migration_in_progress', 'same_volume', 'target_remote', 'target_removable',
  'source_fs_unsupported', 'volume_unknown', 'target_exists_nonempty', 'contains_links',
  'contains_cloud', 'not_enough_space', 'large', 'program_dir',
];
const MIG_KINDS = ['image', 'current_dir', 'open_file', 'service'];
const MIG_PROTECT = ['this_app', 'critical', 'explorer', 'service_host'];
const MIG_STOP = ['exited', 'forced', 'service_stopped', 'already_gone', 'still_running', 'refused', 'failed'];
const MIG_STAGES = ['copying', 'verifying', 'switching', 'cleaning'];
const MIG_STATUS = ['copying', 'switching', 'done', 'restoring', 'failed', 'restored'];
const SYS_ACTIONS = ['recycle_bin', 'hibernation', 'component_store', 'windows_old', 'shadow_copy'];
const ERROR_CODES = [
  'unsupported_platform', 'invalid_path', 'scan_failed', 'unknown_rule', 'no_plan', 'no_scan',
  'journal_failed', 'invalid_exclusion', 'settings_failed', 'policy', 'internal', 'unknown',
  'must_keep_one', 'keeper_changed', 'changed_since_scan', 'invalid_selection', 'nothing_selected',
  'unknown_action', 'sys_failed', 'unknown_app', 'no_uninstaller', 'invalid_command',
  'uninstall_failed', 'backup_failed', 'mig_preflight', 'mig_copy_failed', 'mig_verify_failed',
  'mig_in_use', 'mig_link_failed', 'mig_manifest', 'mig_not_restorable', 'unknown_migration',
  'no_blockers', 'cancelled', 'cloud_location', 'invalid_skip_path',
];

describe('locales', () => {
  it('have identical key sets', () => {
    expect(Object.keys(zh).sort()).toEqual(Object.keys(en).sort());
  });

  it('have no empty strings', () => {
    for (const d of [zh, en]) for (const [k, v] of Object.entries(d)) expect(v.trim(), k).not.toBe('');
  });

  it('use the same placeholders in both languages', () => {
    const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const k of Object.keys(zh)) expect(ph(zh[k]), k).toEqual(ph(en[k]));
  });

  it('cover every rule, skip reason and error code', () => {
    for (const d of [zh, en]) {
      for (const id of RULE_IDS) {
        expect(d[`rule.${id}.name`], id).toBeTruthy();
        expect(d[`rule.${id}.desc`], id).toBeTruthy();
      }
      for (const r of SKIP_REASONS) expect(d[`skip.${r}`], r).toBeTruthy();
      for (const k of MIG_ISSUES) expect(d[`mig.issue.${k}`], k).toBeTruthy();
      for (const k of MIG_KINDS) expect(d[`mig.kind.${k}`], k).toBeTruthy();
      for (const k of MIG_PROTECT) expect(d[`mig.protect.${k}`], k).toBeTruthy();
      for (const k of MIG_STOP) expect(d[`mig.stopStatus.${k}`], k).toBeTruthy();
      for (const k of MIG_STAGES) expect(d[`mig.stage.${k}`], k).toBeTruthy();
      for (const k of MIG_STATUS) expect(d[`mig.status.${k}`], k).toBeTruthy();
      for (const r of LEFTOVER_REASONS) expect(d[`un.reason.${r}`], r).toBeTruthy();
      for (const a of SYS_ACTIONS) for (const k of ['name', 'desc', 'warn']) expect(d[`sys.${a}.${k}`], a).toBeTruthy();
      for (const c of FALLBACK_CODES) expect(d[`scan.fallback.${c}`], c).toBeTruthy();
      for (const c of ERROR_CODES) expect(d[`err.${c}`], c).toBeTruthy();
    }
  });
});
