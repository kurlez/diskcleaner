<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { errorText, i18n, setLocale, t } from '../lib/i18n.svelte';

  let exclusions = $state<string[]>([]);
  let draft = $state('');
  let error = $state('');
  let busy = $state(false);

  onMount(async () => {
    try {
      exclusions = (await api.settingsGet()).exclusions;
    } catch (e) {
      error = errorText(e);
    }
  });

  async function save(next: string[]) {
    busy = true;
    error = '';
    try {
      exclusions = (await api.settingsSetExclusions(next)).exclusions;
      return true;
    } catch (e) {
      error = errorText(e);
      return false;
    } finally {
      busy = false;
    }
  }

  async function add() {
    const p = draft.trim();
    if (!p || exclusions.includes(p)) return;
    if (await save([...exclusions, p])) draft = '';
  }
</script>

<h1>{t('settings.title')}</h1>

<div class="card block">
  <h2>{t('settings.language')}</h2>
  <div class="row seg" role="group" aria-label={t('settings.language')}>
    <button class:primary={i18n.locale === 'zh'} aria-pressed={i18n.locale === 'zh'} onclick={() => setLocale('zh')}>中文</button>
    <button class:primary={i18n.locale === 'en'} aria-pressed={i18n.locale === 'en'} onclick={() => setLocale('en')}>English</button>
  </div>
</div>

<div class="card block">
  <h2>{t('settings.exclusions')}</h2>
  <p class="muted hint">{t('settings.exclusionsHint')}</p>
  <form class="row" onsubmit={(e) => { e.preventDefault(); add(); }}>
    <input type="text" class="grow" bind:value={draft} placeholder={t('settings.placeholder')} spellcheck="false" aria-label={t('settings.exclusions')} />
    <button type="submit" class="primary" disabled={busy || !draft.trim()}>{t('settings.add')}</button>
  </form>
  {#if error}<div class="error" role="alert">{error}</div>{/if}
  {#if exclusions.length === 0}
    <p class="muted">{t('settings.empty')}</p>
  {:else}
    <ul>
      {#each exclusions as p (p)}
        <li class="row">
          <span class="mono grow ellipsis" title={p}>{p}</span>
          <button class="link" disabled={busy} onclick={() => save(exclusions.filter((x) => x !== p))}>{t('settings.remove')}</button>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<p class="muted about">{t('settings.about')}</p>

<style>
  .block { margin-top: 16px; display: flex; flex-direction: column; gap: 10px; }
  .hint { margin-bottom: 2px; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  li { padding: 4px 0; border-bottom: 1px solid var(--border); }
  .about { margin-top: 20px; font-size: 12.5px; }
</style>
