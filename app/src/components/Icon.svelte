<script lang="ts">
  import type { IconKind } from '../lib/fileicon';

  let { kind, open = false, size = 18 }: { kind: IconKind; open?: boolean; size?: number } = $props();

  // 文件图标：页面轮廓 + 类别颜色 + 中间的小图案。图案用 24×24 坐标，落在页面中部。
  const COLOR: Record<string, string> = {
    folder: '#e0a526', file: '#94a3b8', image: '#16a34a', video: '#9333ea', audio: '#db2777',
    archive: '#d97706', disk: '#0ea5e9', exe: '#64748b', pdf: '#dc2626', doc: '#2563eb',
    sheet: '#15803d', slide: '#ea580c', code: '#0d9488', db: '#7c3aed', log: '#78716c',
    text: '#78716c', font: '#a16207', config: '#6b7280', link: '#0891b2', regkey: '#6366f1', regvalue: '#8b5cf6',
  };
  const GLYPH: Record<string, string> = {
    image: 'M8 18l3-4 2 2.5 1.5-2L17 18z',
    video: 'M10 12.5v5l5-2.5z',
    audio: 'M10.5 18a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM12 16.5V12l4-1v4',
    archive: 'M12 9.5v1.5M12 12.5v1.5M12 15.5v1.5M12 18v.5',
    disk: 'M8 13c0-1 8-1 8 0s-8 1-8 0zM8 13v4.5c0 1 8 1 8 0V13',
    exe: 'M8.5 12h7v6h-7zM8.5 14h7',
    doc: 'M8.5 12.5h7M8.5 15h7M8.5 17.5h4.5',
    text: 'M8.5 12.5h7M8.5 15h7M8.5 17.5h4.5',
    log: 'M8.5 12.5h7M8.5 15h5M8.5 17.5h6',
    sheet: 'M8.5 12h7M8.5 15h7M8.5 18h7M11.5 12v6M14 12v6',
    slide: 'M8.5 12h7v5h-7zM12 17v1.5M10.5 18.5h3',
    code: 'M10.5 12.5L8 15l2.5 2.5M13.5 12.5L16 15l-2.5 2.5',
    db: 'M8.5 12.5c0-1 7-1 7 0s-7 1-7 0zM8.5 12.5v5c0 1 7 1 7 0v-5M8.5 15c0 1 7 1 7 0',
    font: 'M9 18l3-7 3 7M10.2 15.5h3.6',
    config: 'M12 13.2a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 11.5v1M12 18.5v-1M8.5 15h1M14.5 15h1',
    link: 'M9 18l6-6M11 12h4v4',
    regvalue: 'M8.5 12.5h7M8.5 15h7M8.5 17.5h4.5',
  };

  const color = $derived(COLOR[kind] ?? COLOR.file);
  const isFolder = $derived(kind === 'folder');
</script>

<svg viewBox="0 0 24 24" width={size} height={size} class="ic" aria-hidden="true" style="--c:{color}">
  {#if isFolder}
    {#if open}
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h7a1.5 1.5 0 0 1 1.5 1.5V11" class="fill" />
      <path d="M5 11h16.5l-2 7.5H4z" class="solid" />
    {:else}
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z" class="solid" />
    {/if}
  {:else if kind === 'regkey'}
    <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z" class="fill" />
    <path d="M9.5 15.5a2 2 0 1 1 0-.01M11.5 13.5H17M15 13.5v2" class="stroke" />
  {:else}
    <path d="M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" class="fill" />
    <path d="M14 3v5h5" class="stroke thin" />
    {#if kind === 'pdf'}
      <text x="12" y="18" text-anchor="middle" class="label">PDF</text>
    {:else if GLYPH[kind]}
      <path d={GLYPH[kind]} class="stroke" />
    {/if}
  {/if}
</svg>

<style>
  .ic { flex: none; display: block; }
  .solid { fill: var(--c); stroke: none; }
  .fill { fill: color-mix(in srgb, var(--c) 18%, transparent); stroke: var(--c); stroke-width: 1.4; stroke-linejoin: round; }
  .stroke { fill: none; stroke: var(--c); stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
  .thin { stroke-width: 1.2; }
  .label { fill: var(--c); font: 700 6px sans-serif; }
</style>
