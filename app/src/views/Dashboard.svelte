<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { goScan, nav } from '../lib/nav.svelte';
  import type { Drive } from '../lib/types';

  let drives = $state<Drive[] | null>(null);
  let error = $state('');

  async function load() {
    error = '';
    try {
      drives = await api.listDrives();
    } catch (e) {
      error = errorText(e);
      drives = [];
    }
  }
  onMount(load);

  const used = (d: Drive) => d.total - d.free;
  const level = (d: Drive) => (percent(used(d), d.total) >= 90 ? 'danger' : percent(used(d), d.total) >= 80 ? 'warn' : '');
</script>

<h1>{t('dash.title')}</h1>
<p class="muted lead">{t('dash.subtitle')}</p>

{#if error}
  <div class="error" role="alert">{error} <button class="link" onclick={load}>{t('common.retry')}</button></div>
{:else if drives === null}
  <p class="muted">{t('common.loading')}</p>
{:else if drives.length === 0}
  <p class="muted">{t('dash.empty')}</p>
{:else}
  <div class="grid">
    {#each drives as d (d.mount)}
      <article class="card">
        <div class="row head">
          <strong class="mount">{d.mount}</strong>
          <span class="muted grow ellipsis">{d.name}</span>
          <span class="badge">{d.fs}</span>
        </div>
        <div class="bar {level(d)}" role="img" aria-label={t('dash.usedPct', { pct: Math.round(percent(used(d), d.total)) })}>
          <i style="width:{percent(used(d), d.total)}%"></i>
        </div>
        <div class="row meta">
          <span class="num">{t('dash.free', { free: formatSize(d.free), total: formatSize(d.total) })}</span>
          <span class="muted grow" style="text-align:right">{t('dash.usedPct', { pct: Math.round(percent(used(d), d.total)) })}</span>
        </div>
        <div class="row actions">
          <button onclick={() => goScan(d.mount)}>{t('dash.scanDrive')}</button>
          <button class="primary" onclick={() => (nav.view = 'clean')}>{t('dash.cleanNow')}</button>
        </div>
      </article>
    {/each}
  </div>
{/if}

<style>
  .lead { margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
  article { display: flex; flex-direction: column; gap: 12px; }
  .mount { font-size: 18px; }
  .meta { font-size: 13px; }
  .actions { margin-top: 4px; }
</style>
