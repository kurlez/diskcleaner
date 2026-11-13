<script lang="ts">
  import { api } from '../lib/api';
  import { formatDuration, formatSize } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { nav } from '../lib/nav.svelte';
  import { platform } from '../lib/platform.svelte';
  import TreeNode from '../components/TreeNode.svelte';
  import Treemap from '../components/Treemap.svelte';
  import PieChart from '../components/PieChart.svelte';
  import CandidatePanel from '../components/CandidatePanel.svelte';
  import TopFiles from '../components/TopFiles.svelte';
  import Icon from '../components/Icon.svelte';
  import { iconKind } from '../lib/fileicon';
  import { clearCands } from '../lib/candidates.svelte';
  import { refresh } from '../lib/refresh.svelte';
  import { resetTree } from '../lib/tree.svelte';
  import type { Child, ScanProgress, ScanSummary } from '../lib/types';

  let path = $state(nav.scanPath);
  let pathEdited = false;
  // 平台检测完成后（macOS 默认分析主目录）更新默认路径；用户改过就不再覆盖。
  $effect(() => {
    if (platform.ready && !pathEdited && !scanning) path = nav.scanPath;
  });
  let scanning = $state(false);
  let progress = $state<ScanProgress | null>(null);
  let elapsed = $state(0);
  let minSizeMb = $state(1);
  let rootSmall = $state({ size: 0, files: 0 });
  let timer: ReturnType<typeof setInterval> | undefined;
  let summary = $state<ScanSummary | null>(null);
  let rootItems = $state<Child[]>([]);
  let rootHidden = $state(0);
  let error = $state('');
  let view = $state<'list' | 'map' | 'pie'>('pie');
  let mapParts = $state<string[]>([]);
  let treeVersion = $state(0);

  async function start() {
    if (scanning || !path.trim()) return;
    scanning = true;
    error = '';
    summary = null;
    progress = null;
    elapsed = 0;
    const t0 = Date.now();
    timer = setInterval(() => (elapsed = Date.now() - t0), 200);
    mapParts = [];
    clearCands(); // 新扫描会使旧的路径分量失效
    resetTree();
    const unlisten = await api.onScanProgress((p) => (progress = p));
    try {
      summary = await api.scanStart(path.trim(), Math.max(0, Math.floor(Number(minSizeMb) || 0)));
      const c = await api.scanChildren([]);
      rootItems = c.items;
      rootHidden = c.hidden;
      rootSmall = { size: c.small_size, files: c.small_files };
    } catch (e) {
      error = errorText(e);
    } finally {
      unlisten();
      clearInterval(timer);
      scanning = false;
    }
  }

  // 清理、迁移之后直接用后端已更新的扫描结果刷新，不需要重新扫描。
  let lastRefresh = refresh.scan;
  $effect(() => {
    const v = refresh.scan;
    if (v === lastRefresh) return;
    lastRefresh = v;
    if (!summary || scanning) return;
    (async () => {
      try {
        summary = await api.scanCurrent();
        const c = await api.scanChildren([]);
        rootItems = c.items;
        rootHidden = c.hidden;
        rootSmall = { size: c.small_size, files: c.small_files };
        treeVersion++;
      } catch {
        /* 没有扫描结果（比如已被新的扫描替换）时忽略 */
      }
    })();
  });

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
    <input type="text" class="grow" bind:value={path} oninput={() => (pathEdited = true)} placeholder={t('scan.pathPlaceholder')} disabled={scanning} spellcheck="false" />
  </label>
  <label class="row" title={t('scan.minSizeHint')}>
    <span class="muted">{t('scan.minSize')}</span>
    <input type="number" min="0" step="1" class="mini" bind:value={minSizeMb} disabled={scanning} />
    <span class="muted">MB</span>
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
    <p class="muted num">{t('scan.elapsed', { time: formatDuration(elapsed) })}</p>
  </div>
{:else if summary}
  <div class="row summary">
    <strong class="big num">{t('scan.total', { size: formatSize(summary.total_size) })}</strong>
    <span class="muted num">{t('scan.files', { n: summary.file_count.toLocaleString() })}</span>
    <span class="muted num">{t('scan.tookTime', { time: formatDuration(summary.elapsed_ms) })}</span>
    <span class="badge method {summary.method}" title={t(`scan.methodHint.${summary.method}`)}>{t(`scan.method.${summary.method}`)}</span>
    <span class="grow"></span>
    <div class="row seg" role="group" aria-label="View">
      <button class:primary={view === 'pie'} aria-pressed={view === 'pie'} onclick={() => (view = 'pie')}>{t('scan.view.pie')}</button>
      <button class:primary={view === 'list'} aria-pressed={view === 'list'} onclick={() => (view = 'list')}>{t('scan.view.list')}</button>
      <button class:primary={view === 'map'} aria-pressed={view === 'map'} onclick={() => (view = 'map')}>{t('scan.view.map')}</button>
    </div>
  </div>
  {#if summary.fallback}<div class="note">{t(`scan.fallback.${summary.fallback}`)}</div>{/if}
  {#if summary.cancelled}<div class="note">{t('scan.cancelledNote')}</div>{/if}
  {#if summary.excluded.length > 0}
    <details class="note excl">
      <summary>{t('cloud.excluded', { n: summary.excluded.length })}</summary>
      <p class="small">{t('cloud.excludedHint')}</p>
      <ul>
        {#each summary.excluded as e}
          <li><span class="mono small">{e.path}</span> <span class="badge">{e.reason === 'custom' ? t('cloud.reason.custom') : e.reason}</span>{#if e.size > 0} <span class="muted small num">{formatSize(e.size)}</span>{/if}</li>
        {/each}
      </ul>
    </details>
  {/if}
  {#if summary.skipped > 0}<p class="muted small">{t('scan.skipped', { n: summary.skipped.toLocaleString() })}</p>{/if}

  {#if summary.min_size > 0}<p class="muted small">{t('scan.minNote', { size: formatSize(summary.min_size) })}</p>{/if}

  {#if view === 'pie'}
    <section class="card" style="margin-top:12px">
      <PieChart rootName={summary.root} bind:parts={mapParts} />
    </section>
  {/if}

  {#if view === 'map'}
    <section class="card" style="margin-top:12px">
      <Treemap rootName={summary.root} bind:parts={mapParts} />
    </section>
  {/if}

  <div class="cols" hidden={view !== 'list'}>
    <section class="card">
      <h2>{t('scan.tree')}</h2>
      <ul class="tree">
        {#key treeVersion}
          {#each rootItems as c (c.name)}
            <TreeNode item={c} parentParts={[]} parentSize={summary.total_size} />
          {/each}
        {/key}
      </ul>
      {#if rootSmall.size > 0}<p class="muted small">{t('scan.smallFolded', { n: rootSmall.files.toLocaleString(), size: formatSize(rootSmall.size) })}</p>{/if}
      {#if rootHidden > 0}<p class="muted small">{t('scan.hidden', { n: rootHidden })}</p>{/if}
    </section>

    <section class="card">
      <h2>{t('scan.topFiles')}</h2>
      <TopFiles files={summary.top_files} root={summary.root} />
    </section>
  </div>
{:else if !error}
  <p class="muted">{t('scan.hint')}</p>
{/if}

<CandidatePanel />

<style>
  .lead { margin-bottom: 16px; }
  .bar-row { margin-bottom: 16px; }
  .bar-row label { gap: 10px; }
  .status { display: flex; flex-direction: column; gap: 6px; }
  .mini { width: 64px; }
  .summary { margin: 8px 0; gap: 14px; }
  .big { font-size: 20px; }
  .excl { margin-top: 8px; }
  .excl summary { cursor: pointer; }
  .excl ul { list-style: none; margin: 6px 0 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  .method.mft { background: var(--accent-soft); color: var(--accent); }
  .note { margin-top: 8px; }
  .cols[hidden] { display: none; }
  .seg { gap: 0; }
  .seg button:first-child { border-radius: 8px 0 0 8px; }
  .seg button:last-child { border-radius: 0 8px 8px 0; margin-left: -1px; }
  .small { font-size: 12.5px; margin: 6px 0; }
  .cols { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(0, 1fr); gap: 16px; margin-top: 12px; align-items: start; }
  @media (max-width: 1080px) { .cols { grid-template-columns: 1fr; } }
  .tree { list-style: none; margin: 0; padding: 0; overflow-x: auto; }
  .cols > .card { min-width: 0; }
</style>
