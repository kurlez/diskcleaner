<script lang="ts">
  import { api } from '../lib/api';
  import { formatSize } from '../lib/format';
  import { iconKind } from '../lib/fileicon';
  import { t } from '../lib/i18n.svelte';
  import { hasCand, toggleCand } from '../lib/candidates.svelte';
  import { breakableName, breakablePath, relParts, splitPath } from '../lib/path';
  import type { FileEntry } from '../lib/types';
  import Icon from './Icon.svelte';

  let { files, root }: { files: FileEntry[]; root: string } = $props();

  let copied = $state<string | null>(null);

  async function copy(path: string) {
    try {
      await navigator.clipboard.writeText(path);
      copied = path;
      setTimeout(() => (copied = copied === path ? null : copied), 1500);
    } catch {
      /* 剪贴板不可用时静默忽略 */
    }
  }

  const rows = $derived(
    files.map((f) => {
      const { dir, name } = splitPath(f.path);
      return { ...f, dir, name, parts: relParts(root, f.path) };
    }),
  );
</script>

<ol class="top">
  {#each rows as f (f.path)}
    <li>
      <span class="size num">{formatSize(f.size)}</span>
      <div class="body" title={f.path}>
        <div class="fname"><Icon kind={iconKind(f.name, false)} size={16} /><strong>{breakableName(f.name)}</strong></div>
        <div class="dir mono">{breakablePath(f.dir)}</div>
      </div>
      <div class="acts">
        {#if f.parts}
          {@const parts = f.parts}
          <button
            class="link"
            class:on={hasCand(parts)}
            title={hasCand(parts) ? t('cand.added') : t('cand.add')}
            aria-label={hasCand(parts) ? t('cand.added') : t('cand.add')}
            aria-pressed={hasCand(parts)}
            onclick={() => toggleCand({ parts, name: f.name, size: f.size, is_dir: false, file_count: 1 })}
          >
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              {#if hasCand(parts)}<path d="M5 12.5l4.5 4.5L19 7.5" />{:else}<path d="M12 5v14M5 12h14" />{/if}
            </svg>
          </button>
          <button class="link" title={t('scan.reveal')} aria-label={t('scan.reveal')} onclick={() => api.reveal(parts).catch(() => {})}>
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M3 7h6l2 2h10v10H3z" /></svg>
          </button>
        {/if}
        <button class="link" title={t('top.copy')} aria-label={t('top.copy')} onclick={() => copy(f.path)}>
          {#if copied === f.path}
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>
          {:else}
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></svg>
          {/if}
        </button>
      </div>
    </li>
  {/each}
</ol>

<style>
  .top { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
  li { display: grid; grid-template-columns: 74px minmax(0, 1fr) auto; gap: 10px; align-items: start; padding: 8px 4px; border-top: 1px solid var(--border); }
  li:first-child { border-top: none; }
  li:hover { background: var(--surface-2); border-radius: 6px; }
  .size { text-align: right; font-weight: 600; padding-top: 1px; }
  .body { min-width: 0; display: flex; flex-direction: column; gap: 2px; }
  .fname { display: flex; align-items: center; gap: 6px; min-width: 0; }
  .fname strong { overflow-wrap: anywhere; }
  /* 目录完整显示，过长时换行，不再截断。 */
  .dir { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; line-height: 1.35; }
  .acts { display: flex; gap: 2px; }
  .acts button { padding: 3px; min-height: 0; color: var(--muted); border-radius: 6px; }
  .acts button:hover { color: var(--accent); }
  .acts button.on { color: var(--accent-text); background: var(--accent); }
</style>
