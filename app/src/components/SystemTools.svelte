<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { formatSize } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import type { SysAction } from '../lib/types';

  let actions = $state<SysAction[] | null>(null);
  let open = $state<string | null>(null);
  let confirmed = $state(false);
  let running = $state<string | null>(null);
  let results = $state<Record<string, { ok: boolean; text: string }>>({});

  async function load() {
    try {
      actions = await api.sysList();
    } catch (e) {
      actions = [];
      results = { _: { ok: false, text: errorText(e) } };
    }
  }
  onMount(load);

  function ask(id: string) {
    open = open === id ? null : id;
    confirmed = false;
  }

  async function run(id: string) {
    running = id;
    try {
      const r = await api.sysRun(id);
      const gained = r.free_before !== null && r.free_after !== null ? r.free_after - r.free_before : 0;
      results[id] = { ok: true, text: gained > 0 ? t('sys.freed', { size: formatSize(gained) }) : t('sys.doneNoChange') };
      open = null;
      await load();
    } catch (e) {
      results[id] = { ok: false, text: errorText(e) };
    } finally {
      running = null;
    }
  }
</script>

<section class="card sys">
  <h2>{t('sys.title')}</h2>
  <p class="muted sub">{t('sys.subtitle')}</p>
  {#if actions === null}
    <p class="muted">{t('sys.loading')}</p>
  {:else}
    <ul>
      {#each actions as a (a.id)}
        <li>
          <div class="row">
            <span class="grow">
              <span class="nm">{t(`sys.${a.id}.name`)}</span>
              <span class="muted desc">{t(`sys.${a.id}.desc`)}</span>
            </span>
            <span class="muted num est">{a.estimate !== null ? t('sys.estimate', { size: formatSize(a.estimate) }) : t('sys.noEstimate')}</span>
            <span class="badge {a.risk}">{t(`clean.risk.${a.risk}`)}</span>
            <button disabled={running !== null} onclick={() => ask(a.id)} aria-expanded={open === a.id}>{t('sys.run')}</button>
          </div>
          {#if open === a.id}
            <div class="confirm">
              <p class="note">{t(`sys.${a.id}.warn`)}</p>
              <label class="opt"><input type="checkbox" bind:checked={confirmed} />{t('sys.confirm')}</label>
              <div class="row"><span class="grow"></span>
                <button class={a.risk === 'high' ? 'danger' : 'primary'} disabled={!confirmed || running !== null} onclick={() => run(a.id)}>
                  {running === a.id ? t('sys.running') : t('sys.go')}
                </button>
              </div>
            </div>
          {/if}
          {#if results[a.id]}
            <p class={results[a.id].ok ? 'okmsg' : 'error'} role="status">{results[a.id].text}</p>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
  {#if results._}<p class="error" role="alert">{results._.text}</p>{/if}
</section>

<style>
  .sys { margin-top: 16px; }
  .sub { margin-bottom: 8px; }
  ul { list-style: none; margin: 0; padding: 0; }
  li { padding: 10px 0; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 8px; }
  li:first-child { border-top: none; }
  .nm { display: block; font-weight: 600; }
  .desc { display: block; font-size: 12.5px; margin-top: 2px; }
  .est { font-size: 12.5px; white-space: nowrap; }
  .confirm { display: flex; flex-direction: column; gap: 10px; padding: 4px 0 2px; }
  .opt { display: flex; gap: 10px; align-items: center; font-weight: 600; }
  .okmsg { color: var(--ok); }
</style>
