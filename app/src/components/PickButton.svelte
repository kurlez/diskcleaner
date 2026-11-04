<script lang="ts">
  import { t } from '../lib/i18n.svelte';
  import { hasCand, toggleCand } from '../lib/candidates.svelte';

  let { parts, name, size, is_dir, file_count, label = false }: {
    parts: string[]; name: string; size: number; is_dir: boolean; file_count: number; label?: boolean;
  } = $props();

  const picked = $derived(hasCand(parts));
  const text = $derived(picked ? t('cand.added') : t('cand.add'));
</script>

<button
  class="link pick"
  class:on={picked}
  class:withlabel={label}
  title={text}
  aria-label={text}
  aria-pressed={picked}
  onclick={(e) => { e.stopPropagation(); toggleCand({ parts, name, size, is_dir, file_count }); }}
>
  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    {#if picked}<path d="M5 12.5l4.5 4.5L19 7.5" />{:else}<path d="M12 5v14M5 12h14" />{/if}
  </svg>
  {#if label}<span>{text}</span>{/if}
</button>

<style>
  .pick { display: inline-flex; align-items: center; gap: 4px; padding: 3px; }
  .pick.on { color: var(--accent); }
  .withlabel { padding: 3px 8px; border: 1px solid var(--border); border-radius: 6px; }
</style>
