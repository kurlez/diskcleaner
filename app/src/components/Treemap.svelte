<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { groupSmall, hueOf, squarify, type Tile } from '../lib/treemap';
  import { refresh } from '../lib/refresh.svelte';
  import type { Child } from '../lib/types';
  import PickButton from './PickButton.svelte';

  let { rootName, parts = $bindable([]) }: { rootName: string; parts: string[] } = $props();

  const HEIGHT = 460;
  const MAX_TILES = 150;
  const MIN_FRACTION = 0.003;

  type Data = { child: Child } | { other: number };

  let width = $state(0);
  let children = $state<Child[]>([]);
  let hidden = $state(0);
  let loading = $state(false);
  let error = $state('');
  let seq = 0;

  // 目录变化时重新取数据；用序号丢弃过期的响应。
  $effect(() => {
    void refresh.scan; // 清理之后重新取当前目录的内容
    const mine = ++seq;
    const target = [...parts];
    loading = true;
    error = '';
    api
      .scanChildren(target)
      .then((c) => {
        if (mine !== seq) return;
        children = c.items;
        hidden = c.hidden;
      })
      .catch((e) => {
        if (mine === seq) error = errorText(e);
      })
      .finally(() => {
        if (mine === seq) loading = false;
      });
  });

  const layout = $derived.by(() => {
    const items = children.map((c) => ({ value: c.size, data: { child: c } as Data }));
    const g = groupSmall(items, MAX_TILES, MIN_FRACTION);
    const all = [...g.kept];
    if (g.otherValue > 0) all.push({ value: g.otherValue, data: { other: g.otherCount + hidden } });
    return squarify(all, { x: 0, y: 0, w: width, h: HEIGHT });
  });

  const total = $derived(children.reduce((a, c) => a + c.size, 0));

  function open(tile: Tile<Data>) {
    if ('child' in tile.data && tile.data.child.is_dir) parts = [...parts, tile.data.child.name];
  }

  const color = (name: string) => `hsl(${hueOf(name)} 48% 40%)`;
  const crumbs = $derived([rootName, ...parts]);
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
    <span class="grow"></span>
    {#if parts.length > 0}
      <PickButton parts={parts} name={parts[parts.length - 1]} size={total} is_dir={true} file_count={children.reduce((a, c) => a + c.file_count, 0)} label />
    {/if}
    <span class="muted num">{formatSize(total)}</span>
  </nav>

  {#if error}<div class="error" role="alert">{error}</div>{/if}

  <div class="map" bind:clientWidth={width} style="height:{HEIGHT}px" aria-busy={loading}>
    {#each layout as tile}
      {@const r = tile.rect}
      {@const label = r.w > 76 && r.h > 38}
      {#if 'child' in tile.data}
        {@const c = tile.data.child}
        <span class="pickwrap" style="left:{r.x + r.w - 28}px;top:{r.y + 3}px" hidden={r.w < 60 || r.h < 34}>
          <PickButton parts={[...parts, c.name]} name={c.name} size={c.size} is_dir={c.is_dir} file_count={c.file_count} />
        </span>
        {#if c.is_dir}
          <button
            class="tile dir"
            style="left:{r.x}px;top:{r.y}px;width:{r.w}px;height:{r.h}px;background:{color(c.name)}"
            title="{c.name} — {formatSize(c.size)}"
            aria-label="{c.name}, {formatSize(c.size)}"
            onclick={() => open(tile)}
          >
            {#if label}<span class="nm">{c.name}</span><span class="sz num">{formatSize(c.size)}</span>{/if}
          </button>
        {:else}
          <div
            class="tile file"
            style="left:{r.x}px;top:{r.y}px;width:{r.w}px;height:{r.h}px"
            title="{c.name} — {formatSize(c.size)}"
            role="img"
            aria-label="{c.name}, {formatSize(c.size)}"
          >
            {#if label}<span class="nm">{c.name}</span><span class="sz num">{formatSize(c.size)}</span>{/if}
          </div>
        {/if}
      {:else}
        <div
          class="tile other"
          style="left:{r.x}px;top:{r.y}px;width:{r.w}px;height:{r.h}px"
          title={t('treemap.other', { n: tile.data.other })}
        >
          {#if label}<span class="nm">{t('treemap.other', { n: tile.data.other })}</span><span class="sz num">{formatSize(tile.value)}</span>{/if}
        </div>
      {/if}
    {/each}
    {#if !loading && layout.length === 0 && !error}
      <p class="empty muted">{t('scan.emptyDir')}</p>
    {/if}
  </div>
  <p class="muted hint">{t('treemap.hint')}</p>
</div>

<style>
  .wrap { display: flex; flex-direction: column; gap: 10px; }
  .crumbs { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; min-height: 28px; }
  .sep { color: var(--muted); }
  .map { position: relative; width: 100%; background: var(--surface-2); border-radius: 8px; overflow: hidden; }
  .tile {
    position: absolute; box-sizing: border-box; border: 1.5px solid var(--surface);
    border-radius: 3px; padding: 5px 7px; overflow: hidden; text-align: left;
    display: flex; flex-direction: column; align-items: flex-start; gap: 1px;
    color: #fff; min-height: 0; font-size: 12.5px; line-height: 1.3;
  }
  button.tile { cursor: pointer; }
  button.tile:hover { filter: brightness(1.15); }
  button.tile:focus-visible { outline: 2px solid var(--accent); outline-offset: -3px; z-index: 1; }
  .file { background: var(--bar); color: var(--text); }
  .other { background: repeating-linear-gradient(45deg, var(--surface-2), var(--surface-2) 6px, var(--bar) 6px, var(--bar) 7px); color: var(--muted); }
  .pickwrap { position: absolute; z-index: 2; background: color-mix(in srgb, var(--surface) 85%, transparent); border-radius: 6px; line-height: 0; }
  .pickwrap[hidden] { display: none; }
  .nm { font-weight: 600; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sz { opacity: 0.85; font-size: 11.5px; }
  .empty { position: absolute; inset: 0; display: grid; place-items: center; }
  .hint { font-size: 12.5px; }
</style>
