<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { nav } from '../lib/nav.svelte';
  import TreeNode from '../components/TreeNode.svelte';
  import type { Child, ScanProgress, ScanSummary } from '../lib/types';

  let path = $state(nav.scanPath);
  let scanning = $state(false);
  let progress = $state<ScanProgress | null>(null);
  let summary = $state<ScanSummary | null>(null);
  let rootItems = $state<Child[]>([]);
  let rootHidden = $state(0);
  let error = $state('');

  async function start() {
    if (scanning || !path.trim()) return;
    scanning = true;
    error = '';
    summary = null;
    progress = null;
    const unlisten = await api.onScanProgress((p) => (progress = p));
    try {
      summary = await api.scanStart(path.trim());
      const c = await api.scanChildren([]);
      rootItems = c.items;
      rootHidden = c.hidden;
    } catch (e) {
      error = errorText(e);
    } finally {
      unlisten();
      scanning = false;
    }
  }

  // 由概览页触发的"分析此盘"。
  let lastRequest = nav.scanRequest;
  $effect(() => {
    if (nav.scanRequest !== lastRequest) {
      lastRequest = nav.scanRequest;
      path = nav.scanPath;
      start();
    }
  });
</script>

<h1>{t('scan.title')}</h1>
<p class="muted lead">{t('scan.subtitle')}</p>

<form class="row bar-row" onsubmit={(e) => { e.preventDefault(); start(); }}>
  <label class="grow row">
    <span class="muted">{t('scan.path')}</span>
    <input type="text" class="grow" bind:value={path} placeholder={t('scan.pathPlaceholder')} disabled={scanning} spellcheck="false" />
  </label>
  {#if scanning}
    <button type="button" onclick={() => api.scanCancel()}>{t('scan.cancel')}</button>
  {:else}
    <button type="submit" class="primary" disabled={!path.trim()}>{t('scan.start')}</button>
  {/if}
</form>

{#if error}<div class="error" role="alert">{error}</div>{/if}

{#if scanning}
  <div class="card status" role="status">
    <p>{t('scan.scanning')}</p>
    {#if progress}
      <p class="muted num">{t('scan.progress', { files: progress.files.toLocaleString(), dirs: progress.dirs.toLocaleString(), size: formatSize(progress.bytes) })}</p>
    {/if}
  </div>
{:else if summary}
  <div class="row summary">
    <strong class="big num">{t('scan.total', { size: formatSize(summary.total_size) })}</strong>
    <span class="muted num">{t('scan.files', { n: summary.file_count.toLocaleString() })}</span>
  </div>
  {#if summary.cancelled}<div class="note">{t('scan.cancelledNote')}</div>{/if}
  {#if summary.skipped > 0}<p class="muted small">{t('scan.skipped', { n: summary.skipped.toLocaleString() })}</p>{/if}

  <div class="cols">
    <section class="card">
      <h2>{t('scan.tree')}</h2>
      <ul class="tree">
        {#each rootItems as c (c.name)}
          <TreeNode item={c} parentParts={[]} parentSize={summary.total_size} />
        {/each}
      </ul>
      {#if rootHidden > 0}<p class="muted small">{t('scan.hidden', { n: rootHidden })}</p>{/if}
    </section>

    <section class="card">
      <h2>{t('scan.topFiles')}</h2>
      <ol class="top">
        {#each summary.top_files as f}
          <li>
            <span class="size num">{formatSize(f.size)}</span>
            <span class="path mono ellipsis" title={f.path}>{f.path}</span>
          </li>
        {/each}
      </ol>
    </section>
  </div>
{:else if !error}
  <p class="muted">{t('scan.hint')}</p>
{/if}

<style>
  .lead { margin-bottom: 16px; }
  .bar-row { margin-bottom: 16px; }
  .bar-row label { gap: 10px; }
  .status { display: flex; flex-direction: column; gap: 6px; }
  .summary { margin: 8px 0; gap: 14px; }
  .big { font-size: 20px; }
  .small { font-size: 12.5px; margin: 6px 0; }
  .cols { display: grid; grid-template-columns: minmax(0, 1.9fr) minmax(0, 1fr); gap: 16px; margin-top: 12px; align-items: start; }
  @media (max-width: 1080px) { .cols { grid-template-columns: 1fr; } }
  .tree { list-style: none; margin: 0; padding: 0; overflow-x: auto; }
  .cols > .card { min-width: 0; }
  .top { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .top li { display: grid; grid-template-columns: 78px 1fr; gap: 8px; align-items: baseline; }
  .size { text-align: right; font-weight: 600; }
</style>
