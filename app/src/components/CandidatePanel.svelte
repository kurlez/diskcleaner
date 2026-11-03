<script lang="ts">
  import { api } from '../lib/api';
  import { analyze, isInside } from '../lib/candidates';
  import { afterChange } from '../lib/refresh.svelte';
  import { cands, clearCands, removeCand } from '../lib/candidates.svelte';
  import { formatSize } from '../lib/format';
  import { iconKind } from '../lib/fileicon';
  import { errorText, t } from '../lib/i18n.svelte';
  import { goMigrate } from '../lib/nav.svelte';
  import type { CandResolved, Report } from '../lib/types';
  import Icon from './Icon.svelte';

  let resolved = $state<Record<string, CandResolved>>({});
  let recycle = $state(true);
  let confirmed = $state(false);
  let busy = $state(false);
  let error = $state('');
  let report = $state<Report | null>(null);

  const info = $derived(analyze(cands.items));

  // 展开或清单变化时，向后端取真实路径与当前状态。
  $effect(() => {
    if (!cands.open || cands.items.length === 0) return;
    const items = [...cands.items];
    api
      .candResolve(items.map((c) => c.parts))
      .then((list) => {
        const m: Record<string, CandResolved> = {};
        items.forEach((c, i) => (m[c.key] = list[i]));
        resolved = m;
      })
      .catch((e) => (error = errorText(e)));
  });

  async function remove() {
    busy = true;
    error = '';
    try {
      const items = info.effective;
      // 先取一份最新的真实路径，之后才能知道哪些项目没处理成功。
      const paths = (await api.candResolve(items.map((c) => c.parts))).map((r) => r.path);
      report = await api.candDelete(items.map((c) => c.parts), recycle);
      // 只移出已经处理掉的项；被拒绝或失败的留在清单里，让用户看到并决定。
      const failed = new Set(report.problems.map((p) => p.path));
      const stay = items.filter((_, i) => failed.has(paths[i]));
      cands.items = cands.items.filter((c) => stay.some((k) => k.key === c.key || isInside(c.parts, k.parts)));
      if (cands.items.length === 0) cands.open = false;
      confirmed = false;
      afterChange(); // 树、合计、最大文件、概览、重复文件立刻刷新
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  // 只有一个有效的目录候选时，可以直接把它交给"目录迁移"。
  const migratable = $derived(
    info.effective.length === 1 && info.effective[0].is_dir ? (resolved[info.effective[0].key]?.path ?? null) : null,
  );

  const skipped = (c: { key: string }) => resolved[c.key] && (!resolved[c.key].exists || resolved[c.key].is_link);
</script>

{#if report}
  <section class="card panel done">
    <div class="row">
      <h2 class="grow">{t('cand.doneTitle')}</h2>
      <button class="link" onclick={() => (report = null)}>×</button>
    </div>
    <p class="big num">{t('report.freed', { size: formatSize(report.freed_bytes) })}</p>
    {#if report.recycled_bytes > 0}<p class="note">{t('report.recycled', { size: formatSize(report.recycled_bytes) })}</p>{/if}
    <p class="muted num">{t('report.counts', { deleted: report.deleted, recycled: report.recycled, failed: report.failed, refused: report.refused })}</p>
    {#each report.problems as p}<p class="mono small ellipsis" title={p.path}>{t(`report.status.${p.status}`)} · {p.path}</p>{/each}
    <p class="muted small">{t('cand.rescan')}</p>
  </section>
{/if}

{#if cands.items.length > 0}
  <section class="card panel basket" aria-label={t('cand.title')}>
    <div class="row">
      <strong>{t('cand.title')}</strong>
      <span class="muted num grow">{t('cand.summary', { n: info.effective.length, size: formatSize(info.totalSize) })}</span>
      <button onclick={() => (cands.open = !cands.open)} aria-expanded={cands.open}>{cands.open ? t('cand.hide') : t('cand.show')}</button>
      <button onclick={clearCands} disabled={busy}>{t('cand.clear')}</button>
    </div>

    {#if cands.open}
      <p class="muted small">{t('cand.hint')}</p>
      {#if error}<div class="error" role="alert">{error}</div>{/if}
      <ul class="list">
        {#each cands.items as c (c.key)}
          {@const r = resolved[c.key]}
          <li class:dim={info.covered.has(c.key) || skipped(c)}>
            <Icon kind={iconKind(c.name, c.is_dir)} />
            <span class="grow">
              <span class="mono path" title={r?.path ?? c.name}>{r?.path ?? c.parts.join('\\')}</span>
              <span class="muted small">
                {#if info.covered.has(c.key)}<span class="badge">{t('cand.covered')}</span>{/if}
                {#if r && !r.exists}<span class="badge high">{t('cand.missing')}</span>{/if}
                {#if r?.is_link}<span class="badge medium">{t('cand.link')}</span>{/if}
              </span>
            </span>
            <span class="muted num size">{formatSize(c.size)}</span>
            <button class="link" aria-label={t('cand.remove')} title={t('cand.remove')} onclick={() => removeCand(c.key)} disabled={busy}>×</button>
          </li>
        {/each}
      </ul>
      <p class="num"><strong>{t('cand.total', { size: formatSize(info.totalSize), files: info.totalFiles.toLocaleString() })}</strong></p>
      <label class="opt"><input type="checkbox" bind:checked={recycle} />{t('cand.recycle')}</label>
      <label class="opt confirm"><input type="checkbox" bind:checked={confirmed} />{t('cand.confirm')}</label>
      <div class="row"><span class="grow"></span>
        {#if migratable}<button onclick={() => goMigrate(migratable!)} disabled={busy}>{t('cand.migrate')}</button>{/if}
        <button class={recycle ? 'primary' : 'danger'} disabled={!confirmed || busy || info.effective.length === 0} onclick={remove}>
          {busy ? t('cand.deleting') : t('cand.delete')}
        </button>
      </div>
    {/if}
  </section>
{/if}

<style>
  .panel { display: flex; flex-direction: column; gap: 8px; margin-top: 12px; }
  .basket { position: sticky; bottom: 8px; box-shadow: 0 -4px 18px rgb(0 0 0 / 12%); z-index: 2; }
  .small { font-size: 12.5px; }
  .big { font-size: 16px; font-weight: 600; }
  .list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; max-height: 280px; overflow: auto; }
  .list li { display: flex; align-items: center; gap: 8px; padding: 5px 6px; border-radius: 6px; }
  .list li:hover { background: var(--surface-2); }
  .list li.dim { opacity: 0.6; }
  .path { display: block; word-break: break-all; }
  .size { min-width: 70px; text-align: right; }
  .opt { display: flex; gap: 10px; align-items: center; }
  .confirm { font-weight: 600; }
</style>
