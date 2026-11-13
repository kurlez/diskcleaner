import { api } from './api';
import { nav } from './nav.svelte';
import type { AppStatus } from './types';

/** 当前运行平台。界面据此切换文案（`xxx.mac` 覆盖 `xxx`）与默认路径。 */
export const platform = $state<{ name: AppStatus['platform']; home: string; fda: boolean | null; elevated: boolean; ready: boolean }>({
  name: 'windows',
  home: '',
  fda: null,
  elevated: true,
  ready: false,
});

export const isMac = () => platform.name === 'macos';

export async function loadPlatform(): Promise<void> {
  try {
    const s = await api.appStatus();
    platform.name = s.platform;
    platform.home = s.home;
    platform.fda = s.full_disk_access;
    platform.elevated = s.elevated;
    // macOS 没有盘符：默认分析用户主目录（根目录会把系统和其他卷混在一起）。
    if (s.platform === 'macos' && s.home) nav.scanPath = s.home;
  } catch {
    /* 取不到时保持默认（Windows） */
  } finally {
    platform.ready = true;
  }
}

/** 重新检测"完全磁盘访问权限"（用户在系统设置里授权回来之后）。 */
export async function refreshPlatform(): Promise<void> {
  try {
    const s = await api.appStatus();
    platform.fda = s.full_disk_access;
    platform.elevated = s.elevated;
  } catch {
    /* ignore */
  }
}
