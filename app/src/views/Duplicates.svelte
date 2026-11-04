<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, i18n, t } from '../lib/i18n.svelte';
  import { afterChange, refresh } from '../lib/refresh.svelte';
  import Icon from '../components/Icon.svelte';
  import { iconKind } from '../lib/fileicon';
  import type { DupGroup, DupProgress, DupSummary, Report } from '../lib/types';

  let path = $state('');
  let minSize = $state(10);
  let scanning = $state(false);
  let deleting = $state(false);
  let progress = $state<DupProgress | null>(null);
  let summary = $state<DupSummary | null>(null);
  let report = $state<Report | null>(null);
  let error = $state('');

  let selected = $state<Set<string>>(new Set());
  let recycle = $state(true);
  let confirmed = $state(false);

  const key = (g: number, f: number) => `${g}:${f}`;

  function suggested(groups: DupGroup[]): Set<string> {
    const s = new Set<string>();
    for (const g of groups) g.files.forEach((_, i) => i !== g.keep && s.add(key(g.id, i)));
    return s;
  }

  async function scan() {
    if (scanning || !path.trim()) return;
    scanning = true;
    error = '';
    report = null;
    summary = null;
    progress = null;
    confirmed = false;
    const un = await api.onDupProgress((p) => (progress = p));
    try {
      summary = await api.dupScan(path.trim(), minSize);
      selected = suggested(summary.groups);
    } catch (e) {
      error = errorText(e);
    } finally {
      un();
      scanning = false;
    }
  }

  // 一组里只剩最后一个未勾选的文件时，不允许再勾它。
  function lockedLast(g: DupGroup, i: number): boolean {
    if (selected.has(key(g.id, i))) return false;
    return g.files.filter((_, j) => !selected.has(key(g.id, j))).length <= 1;
  }

  function toggle(g: DupGroup, i: number) {
    const k = key(g.id, i);
    const next = new Set(selected);
    if (next.has(k)) next.delete(k);
    else if (!lockedLast(g, i)) next.add(k);
    selected = next;
    confirmed = false;
  }

  const selectedSize = $derived(
    summary ? summary.groups.reduce((a, g) => a + g.files.filter((_, i) => selected.has(key(g.id, i))).length * g.size, 0) : 0,
  );

  async function remove() {
    if (!summary) return;
    deleting = true;
    error = '';
    const sel = [...selected].map((k) => {
      const [group, file] = k.split(':').map(Number);
      // 同时回传路径：别处的清理让序号错位时，后端会拒绝而不是删到别的文件。
      const path = summary!.groups.find((g) => g.id === group)?.files[file]?.path;
      return { group, file, path };
    });
    try {
      report = await api.dupDelete(sel, recycle);
      summary = await api.dupCurrent();
      selected = suggested(summary.groups);
      confirmed = false;
      afterChange();
    } catch (e) {
      error = errorText(e);
    } finally {
      deleting = false;
    }
  }

  // 别处（候选清单、迁移……）清理了文件：立即重新读取，并把选择恢复成推荐值。
  let lastDups = refresh.dups;
  $effect(() => {
    if (refresh.dups === lastDups) return;
    lastDups = refresh.dups;
    if (!summary || scanning || deleting) return;
    api
      .dupCurrent()
      .then((s) => {
        summary = s;
        selected = suggested(s.groups);
        confirmed = false;
      })
      .catch(() => {});
  });

  const date = (secs: number) => new Date(secs * 1000).toLocaleDateString(i18n.locale === 'zh' ? 'zh-CN' : 'en-US');
</script>

<h1>{t('dup.title')}</h1>
<p class="muted lead">{t('dup.subtitle')}</p>

<form class="row form" onsubmit={(e) => { e.preventDefault(); scan(); }}>
  <label class="grow row">
    <span class="muted">{t('dup.path')}</span>
    <input type="text" class="grow" bind:value={path} placeholder={t('dup.pathPlaceholder')} disabled={scanning} spellcheck="false" />
  </label>
  <label class="row">
    <span class="muted">{t('dup.minSize')}</span>
    <input type="number" min="0" bind:value={minSize} disabled={scanning} class="num-in" />
  </label>
  {#if scanning}
    <button type="button" onclick={() => api.dupCancel()}>{t('dup.stop')}</button>
  {:else}
    <button type="submit" class="primary" disabled={!path.trim()}>{t('dup.scan')}</button>
  {/if}
</form>

{#if error}<div class="error" role="alert">{error}</div>{/if}

{#if scanning}
  <div class="card status" role="status">
    <p>{progress ? t(`dup.phase.${progress.phase}`) : t('dup.phase.walking')}</p>
    {#if progress}
      {#if progress.phase === 'walking'}
        <p class="muted num">{t('dup.progressFiles', { done: progress.done.toLocaleString() })}</p>
      {:else}
        <div class="bar"><i style="width:{percent(progress.done, progress.total)}%"></i></div>
        <p class="muted num">{t('dup.progressHash', { done: progress.done, total: progress.total })}</p>
      {/if}
    {/if}
  </div>
{/if}

{#if report}
  <div class="card done">
    <h2>{t('dup.doneTitle')}</h2>
    <p class="big num">{t('report.freed', { size: formatSize(report.freed_bytes) })}</p>
    {#if report.recycled_bytes > 0}<p class="note">{t('report.recycled', { size: formatSize(report.recycled_bytes) })}</p>{/if}
    <p class="muted num">{t('report.counts', { deleted: report.deleted, recycled: report.recycled, failed: report.failed, refused: report.refused })}</p>
    {#each report.problems as p}
      <p class="mono small ellipsis" title={p.path}>{t(`report.status.${p.status}`)} · {p.path}</p>
    {/each}
  </div>
{/if}

{#if summary && !scanning}
  {#if summary.cancelled}<div class="note">{t('dup.cancelledNote')}</div>{/if}
  {#if summary.excluded.length > 0}<p class="muted small">{t('cloud.excluded', { n: summary.excluded.length })}</p>{/if}
  {#if summary.groups.length === 0}
    <p class="muted empty">{t('dup.none')}</p>
  {:else}
    <div class="row head">
      <strong class="big">{t('dup.found', { n: summary.groups.length + summary.hidden_groups, size: formatSize(summary.total_wasted) })}</strong>
    </div>
    <p class="muted small">{t('dup.checked', { n: summary.scanned_files.toLocaleString() })}{#if summary.errors > 0} · {t('dup.unreadable', { n: summary.errors })}{/if}</p>
    <p class="muted small">{t('dup.suggestHint')} {t('dup.lastCopy')}</p>

    <div class="groups">
      {#each summary.groups as g (g.id)}
        <section class="card">
          <h2>{t('dup.copies', { n: g.files.length, size: formatSize(g.size), wasted: formatSize(g.wasted) })}</h2>
          <ul>
            {#each g.files as f, i}
              <li class:marked={selected.has(key(g.id, i))}>
                <label class="row">
                  <input type="checkbox" checked={selected.has(key(g.id, i))} disabled={lockedLast(g, i) || deleting} onchange={() => toggle(g, i)} aria-label={f.path} />
                  <Icon kind={iconKind(f.path.split(/[\\/]/).pop() ?? '', false)} size={16} />
                  <span class="mono grow ellipsis" title={f.path}>{f.path}</span>
                  {#if i === g.keep && !selected.has(key(g.id, i))}<span class="badge low">{t('dup.keepBadge')}</span>{/if}
                  <span class="muted small nowrap">{t('dup.modified', { date: date(f.modified) })}</span>
                </label>
              </li>
            {/each}
          </ul>
        </section>
      {/each}
    </div>
    {#if summary.hidden_groups > 0}<p class="muted small">{t('dup.hidden', { n: summary.hidden_groups })}</p>{/if}

    <div class="card actions">
      <div class="row">
        <strong class="grow num">{t('dup.selected', { n: selected.size, size: formatSize(selectedSize) })}</strong>
        <button onclick={() => (selected = new Set())}>{t('dup.selectNone')}</button>
        <button onclick={() => (selected = suggested(summary!.groups))}>{t('dup.selectSuggested')}</button>
      </div>
      <label class="opt"><input type="checkbox" bind:checked={recycle} />
        <span>{t('dup.recycle')}<br /><span class="muted small">{t('dup.recycleHint')}</span></span>
      </label>
      <label class="opt confirm"><input type="checkbox" bind:checked={confirmed} />{t('dup.confirm')}</label>
      <div class="row"><span class="grow"></span>
        <button class={recycle ? 'primary' : 'danger'} disabled={selected.size === 0 || !confirmed || deleting} onclick={remove}>
          {deleting ? t('dup.deleting') : t('dup.delete')}
        </button>
      </div>
    </div>
  {/if}
{/if}

<style>
  .lead { margin-bottom: 16px; }
  .form { margin-bottom: 16px; gap: 14px; flex-wrap: wrap; }
  .form label { gap: 8px; }
  .num-in { width: 80px; font: inherit; color: inherit; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 7px 10px; min-height: 34px; }
  .status { display: flex; flex-direction: column; gap: 8px; }
  .big { font-size: 16px; }
  .small { font-size: 12.5px; margin-top: 4px; }
  .nowrap { white-space: nowrap; }
  .empty { padding: 20px 0; }
  .head { margin-top: 6px; }
  .groups { display: flex; flex-direction: column; gap: 12px; margin-top: 12px; }
  .groups ul { list-style: none; margin: 8px 0 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
  .groups li { padding: 5px 8px; border-radius: 6px; }
  .groups li.marked { background: var(--danger-soft); }
  .groups label { cursor: pointer; }
  .actions { margin-top: 16px; display: flex; flex-direction: column; gap: 12px; position: sticky; bottom: 0; }
  .opt { display: flex; gap: 10px; align-items: flex-start; }
  .confirm { font-weight: 600; padding-top: 8px; border-top: 1px solid var(--border); }
  .done { margin-bottom: 14px; display: flex; flex-direction: column; gap: 6px; }
</style>
