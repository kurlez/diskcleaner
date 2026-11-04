<script lang="ts">
  import { api } from '../lib/api';
  import { errorText, t } from '../lib/i18n.svelte';

  let elevated = $state(true);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    api.appStatus().then((s) => (elevated = s.elevated)).catch(() => {});
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
</script>

{#if !elevated}
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
  .err { color: var(--danger, #c62828); }
  button { white-space: nowrap; }
</style>
