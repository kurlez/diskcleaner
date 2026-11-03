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
const ERROR_CODES = [
  'unsupported_platform', 'invalid_path', 'scan_failed', 'unknown_rule', 'no_plan', 'no_scan',
  'journal_failed', 'invalid_exclusion', 'settings_failed', 'policy', 'internal', 'unknown',
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
      for (const c of ERROR_CODES) expect(d[`err.${c}`], c).toBeTruthy();
    }
  });
});
