import { en } from './locales/en';
import { zh } from './locales/zh';
import { platform } from './platform.svelte';
import type { ApiError } from './types';

export type Locale = 'zh' | 'en';
const dicts: Record<Locale, Record<string, string>> = { zh, en };

function initialLocale(): Locale {
  try {
    const saved = localStorage.getItem('locale');
    if (saved === 'zh' || saved === 'en') return saved;
  } catch {
    /* localStorage 不可用时忽略 */
  }
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

export const i18n = $state<{ locale: Locale }>({ locale: initialLocale() });

export function setLocale(l: Locale) {
  i18n.locale = l;
  document.documentElement.lang = l === 'zh' ? 'zh-CN' : 'en';
  try {
    localStorage.setItem('locale', l);
  } catch {
    /* ignore */
  }
}

/** 翻译；缺失的键回退到另一种语言，再回退到键名本身。 */
export function t(key: string, params: Record<string, string | number> = {}): string {
  const other: Locale = i18n.locale === 'zh' ? 'en' : 'zh';
  // macOS 下优先用 `key.mac` 的文案（路径示例、"访达"、"废纸篓"等）。
  const macKey = platform.name === 'macos' ? `${key}.mac` : '';
  const raw =
    (macKey && (dicts[i18n.locale][macKey] ?? dicts[other][macKey])) ||
    dicts[i18n.locale][key] ||
    dicts[other][key] ||
    key;
  return raw.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
}

/** 把后端错误（或任何异常）转成可展示的文字。 */
export function errorText(e: unknown): string {
  const err = e as Partial<ApiError> | undefined;
  if (err && typeof err === 'object' && typeof err.code === 'string') {
    const base = t(`err.${err.code}`);
    const msg = base === `err.${err.code}` ? t('err.unknown') : base;
    return err.detail ? `${msg} (${err.detail})` : msg;
  }
  return t('err.unknown');
}
