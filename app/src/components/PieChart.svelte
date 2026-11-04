<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { arcPath, pieSlices } from '../lib/pie';
  import { hueOf } from '../lib/treemap';
  import { refresh } from '../lib/refresh.svelte';
  import Icon from './Icon.svelte';
  import { iconKind } from '../lib/fileicon';
  import type { Child } from '../lib/types';

  let { rootName, parts = $bindable([]) }: { rootName: string; parts: string[] } = $props();

  const SIZE = 300;
  const C = SIZE / 2;

  let children = $state<Child[]>([]);
  let smallSize = $state(0);
  let smallFiles = $state(0);
  let hidden = $state(0);
  let loading = $state(false);
  let error = $state('');
  let hover = $state<number | null>(null);
  let seq = 0;

  $effect(() => {
    void refresh.scan;
    const mine = ++seq;
    const target = [...parts];
    loading = true;
    error = '';
    api
      .scanChildren(target)
      .then((c) => {
        if (mine !== seq) return;
        children = c.items;
        smallSize = c.small_size;
        smallFiles = c.small_files;
        hidden = c.hidden;
      })
      .catch((e) => {
        if (mine === seq) error = errorText(e);
      })
      .finally(() => {
        if (mine === seq) loading = false;
      });
  });

  const slices = $derived(pieSlices(children, smallSize));
  const total = $derived(slices.reduce((a, s) => a + s.size, 0));
  const crumbs = $derived([rootName, ...parts]);
  const color = (name: string | null) => (name === null ? 'var(--bar)' : `hsl(${hueOf(name)} 50% 42%)`);

  function open(i: number) {
    const it = slices[i]?.item;
    if (it?.is_dir) parts = [...parts, it.name];
  }
</script>

<div class="wrap">
  <nav class="crumbs" aria-label="Path">
    {#each crumbs as c, i}
      {#if i > 0}<span class="sep" aria-hidden="true">›</span>{/if}
      {#if i < crumbs.length - 1}
        <button class="link" onclick={() => (parts = parts.slice(0, i))}>{c}</button>
      {:else}
        <strong>{c}</strong>
      {/if}
    {/each}
  </nav>

  {#if error}<div class="error" role="alert">{error}</div>{/if}

  {#if slices.length === 0 && !loading && !error}
    <p class="muted">{t('scan.emptyDir')}</p>
  {:else}
    <div class="body" aria-busy={loading}>
      <svg viewBox="0 0 {SIZE} {SIZE}" width={SIZE} height={SIZE} role="img" aria-label={t('pie.label')}>
        {#each slices as s, i}
          <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
          <path
            d={arcPath(C, C, hover === i ? 140 : 134, 78, s.start, s.end)}
            fill={color(s.item?.name ?? null)}
            stroke="var(--surface)"
            stroke-width="1.5"
            class:click={s.item?.is_dir}
            role={s.item?.is_dir ? 'button' : 'img'}
            tabindex={s.item?.is_dir ? 0 : undefined}
            aria-label="{s.item?.name ?? t('pie.other')}, {formatSize(s.size)}"
            onclick={() => open(i)}
            onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && open(i)}
            onmouseenter={() => (hover = i)}
            onmouseleave={() => (hover = null)}
          />
        {/each}
        <text x={C} y={C - 4} text-anchor="middle" class="ctr num">{formatSize(total)}</text>
        <text x={C} y={C + 16} text-anchor="middle" class="sub">{hover !== null ? percent(slices[hover].size, total).toFixed(1) + '%' : t('pie.total')}</text>
      </svg>

      <ul class="legend">
        {#each slices as s, i}
          <li class:on={hover === i} onmouseenter={() => (hover = i)} onmouseleave={() => (hover = null)}>
            <i class="dot" style="background:{color(s.item?.name ?? null)}"></i>
            {#if s.item}
              <Icon kind={iconKind(s.item.name, s.item.is_dir)} />
              {#if s.item.is_dir}
                <button class="link name" onclick={() => open(i)}>{s.item.name}</button>
              {:else}
                <span class="name">{s.item.name}</span>
              {/if}
            {:else}
              <span class="name muted">{t('pie.otherN', { n: s.count + hidden })}</span>
            {/if}
            <span class="num sz">{formatSize(s.size)}</span>
            <span class="num pc muted">{percent(s.size, total).toFixed(1)}%</span>
          </li>
        {/each}
      </ul>
    </div>
    {#if smallSize > 0}
      <p class="muted small">{t('pie.small', { n: smallFiles.toLocaleString(), size: formatSize(smallSize) })}</p>
    {/if}
  {/if}
</div>

<style>
  .wrap { display: flex; flex-direction: column; gap: 10px; }
  .crumbs { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; min-height: 28px; }
  .sep { color: var(--muted); }
  .body { display: flex; gap: 28px; align-items: center; flex-wrap: wrap; }
  svg { flex: none; }
  path { transition: d 0.12s; }
  path.click { cursor: pointer; }
  path:focus-visible { outline: none; stroke: var(--accent); stroke-width: 3; }
  .ctr { font-size: 22px; font-weight: 700; fill: var(--text); }
  .sub { font-size: 12px; fill: var(--muted); }
  .legend { list-style: none; margin: 0; padding: 0; flex: 1; min-width: 260px; display: flex; flex-direction: column; gap: 2px; }
  .legend li { display: flex; align-items: center; gap: 8px; padding: 5px 8px; border-radius: 6px; }
  .legend li.on { background: var(--surface-2); }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: left; }
  .sz { min-width: 70px; text-align: right; }
  .pc { min-width: 48px; text-align: right; }
</style>
