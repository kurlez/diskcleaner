<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { errorText, t } from '../lib/i18n.svelte';
  import { platform, refreshPlatform } from '../lib/platform.svelte';

  let busy = $state(false);
  let error = $state('');

  // 用户从系统设置授权回来后，窗口重新获得焦点时自动重新检测。
  onMount(() => {
    const onFocus = () => void refreshPlatform();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  });

  async function restart() {
    busy = true;
    error = '';
    try {
      await api.relaunchAsAdmin();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function openSettings() {
    error = '';
    try {
      await api.openPrivacySettings();
    } catch (e) {
      error = errorText(e);
    }
  }

  const needFda = $derived(platform.name === 'macos' && platform.fda === false);
  const needAdmin = $derived(platform.name === 'windows' && !platform.elevated);
</script>

{#if needFda}
  <div class="admin" role="alert">
    <div class="msg">
      <strong>{t('fda.title')}</strong>
      <span>{t('fda.desc')}</span>
      {#if error}<span class="err">{error}</span>{/if}
    </div>
    <div class="acts">
      <button class="primary" onclick={openSettings}>{t('fda.open')}</button>
      <button onclick={() => refreshPlatform()}>{t('fda.recheck')}</button>
    </div>
  </div>
{:else if needAdmin}
  <div class="admin" role="alert">
    <div class="msg">
      <strong>{t('admin.title')}</strong>
      <span>{t('admin.desc')}</span>
      {#if error}<span class="err">{error}</span>{/if}
    </div>
    <button class="primary" onclick={restart} disabled={busy}>{t('admin.restart')}</button>
  </div>
{/if}

<style>
  .admin { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 10px 14px; margin-bottom: 16px; border: 1px solid var(--warn, #d9a400); background: color-mix(in srgb, var(--warn, #d9a400) 12%, transparent); border-radius: 8px; }
  .msg { display: flex; flex-direction: column; gap: 2px; font-size: 13px; }
  .acts { display: flex; gap: 8px; }
  .err { color: var(--danger, #c62828); }
  button { white-space: nowrap; }
</style>
