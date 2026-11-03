<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import type { Child } from '../lib/types';
  import TreeNode from './TreeNode.svelte';

  let { item, parentParts, parentSize, depth = 0 }: {
    item: Child; parentParts: string[]; parentSize: number; depth?: number;
  } = $props();

  let open = $state(false);
  let loading = $state(false);
  let error = $state('');
  let kids = $state<{ items: Child[]; hidden: number } | null>(null);

  const parts = $derived([...parentParts, item.name]);

  async function toggle() {
    if (!item.is_dir) return;
    open = !open;
    if (open && !kids) {
      loading = true;
      error = '';
      try {
        kids = await api.scanChildren(parts);
      } catch (e) {
        error = errorText(e);
        open = false;
      } finally {
        loading = false;
      }
    }
  }
</script>

<li>
  <div class="line" style="padding-left:{depth * 18}px">
    {#if item.is_dir}
      <button class="caret" onclick={toggle} aria-expanded={open} aria-label={item.name}>
        <svg viewBox="0 0 24 24" width="14" height="14" class:rot={open} fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><path d="M9 6l6 6-6 6" /></svg>
      </button>
    {:else}
      <span class="caret"></span>
    {/if}
    <span class="name ellipsis" title={item.name}>{item.name}</span>
    <span class="bar" aria-hidden="true"><i style="width:{percent(item.size, parentSize)}%"></i></span>
    <span class="size num">{formatSize(item.size)}</span>
    <span class="count muted num">{t('scan.files', { n: item.file_count.toLocaleString() })}</span>
    <button class="link rev" title={t('scan.reveal')} aria-label={t('scan.reveal')} onclick={() => api.reveal(parts).catch(() => {})}>
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M3 7h6l2 2h10v10H3z" /></svg>
    </button>
  </div>
  {#if error}<div class="error" style="margin-left:{depth * 18 + 24}px">{error}</div>{/if}
  {#if open}
    <ul>
      {#if loading}
        <li class="muted" style="padding-left:{(depth + 1) * 18 + 24}px">{t('common.loading')}</li>
      {:else if kids}
        {#each kids.items as c (c.name)}
          <TreeNode item={c} parentParts={parts} parentSize={item.size} depth={depth + 1} />
        {:else}
          <li class="muted" style="padding-left:{(depth + 1) * 18 + 24}px">{t('scan.emptyDir')}</li>
        {/each}
        {#if kids.hidden > 0}
          <li class="muted" style="padding-left:{(depth + 1) * 18 + 24}px">{t('scan.hidden', { n: kids.hidden })}</li>
        {/if}
      {/if}
    </ul>
  {/if}
</li>

<style>
  ul { list-style: none; margin: 0; padding: 0; }
  li { list-style: none; min-width: 0; }
  .line { display: grid; grid-template-columns: 22px minmax(60px, 1fr) 72px 76px 92px 24px; align-items: center; gap: 8px; padding-top: 4px; padding-bottom: 4px; border-radius: 6px; }
  .line:hover { background: var(--surface-2); }
  .caret { width: 22px; height: 22px; padding: 0; min-height: 0; border: none; background: none; display: inline-flex; align-items: center; justify-content: center; color: var(--muted); }
  svg.rot { transform: rotate(90deg); }
  .bar { height: 6px; }
  .size { text-align: right; }
  .count { font-size: 12px; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rev { padding: 2px; }
</style>
