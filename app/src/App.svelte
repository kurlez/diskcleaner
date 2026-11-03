<script lang="ts">
  import { i18n, setLocale, t } from './lib/i18n.svelte';
  import { nav, type View } from './lib/nav.svelte';
  import Dashboard from './views/Dashboard.svelte';
  import Scan from './views/Scan.svelte';
  import Clean from './views/Clean.svelte';
  import SettingsView from './views/Settings.svelte';

  setLocale(i18n.locale);

  const items: { view: View; key: string; icon: string }[] = [
    { view: 'dashboard', key: 'nav.dashboard', icon: 'M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10' },
    { view: 'scan', key: 'nav.scan', icon: 'M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5' },
    { view: 'clean', key: 'nav.clean', icon: 'M4 20l6-6M14 4l6 6-8 8-6-6 8-8z' },
    { view: 'settings', key: 'nav.settings', icon: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19 12a7 7 0 00-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 00-2-1.2L14 3h-4l-.6 2.6a7 7 0 00-2 1.2l-2.3-.9-2 3.4 2 1.5A7 7 0 005 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.3-.9a7 7 0 002 1.2L10 21h4l.6-2.6a7 7 0 002-1.2l2.3.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z' },
  ];
</script>

<div class="shell">
  <nav class="side" aria-label="Main">
    <div class="brand">
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><circle cx="12" cy="12" r="10" fill="var(--accent)" /><circle cx="12" cy="12" r="3.5" fill="var(--accent-text)" /></svg>
      <span>{t('app.title')}</span>
    </div>
    <ul>
      {#each items as it}
        <li>
          <button class="navbtn" class:active={nav.view === it.view} aria-current={nav.view === it.view ? 'page' : undefined} onclick={() => (nav.view = it.view)}>
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={it.icon} /></svg>
            {t(it.key)}
          </button>
        </li>
      {/each}
    </ul>
    <label class="lang">
      <span class="sr-only">{t('settings.language')}</span>
      <select value={i18n.locale} onchange={(e) => setLocale(e.currentTarget.value as 'zh' | 'en')}>
        <option value="zh">中文</option>
        <option value="en">English</option>
      </select>
    </label>
  </nav>

  <main>
    <section hidden={nav.view !== 'dashboard'}><Dashboard /></section>
    <section hidden={nav.view !== 'scan'}><Scan /></section>
    <section hidden={nav.view !== 'clean'}><Clean /></section>
    <section hidden={nav.view !== 'settings'}><SettingsView /></section>
  </main>
</div>

<style>
  .shell { display: grid; grid-template-columns: 220px 1fr; height: 100%; }
  .side { background: var(--surface); border-right: 1px solid var(--border); padding: 16px 12px; display: flex; flex-direction: column; gap: 14px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; padding: 4px 8px; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; flex: 1; }
  .navbtn { width: 100%; display: flex; align-items: center; gap: 10px; border: none; background: none; text-align: left; padding: 9px 10px; }
  .navbtn.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
  .lang select { width: 100%; }
  main { overflow: auto; padding: 24px 28px; }
  section[hidden] { display: none; }
  section { max-width: 980px; }
</style>
