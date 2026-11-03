<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, i18n, t } from '../lib/i18n.svelte';
  import { cleanPath, driveOf, parseSpace, suggestTarget } from '../lib/migrate';
  import { nav } from '../lib/nav.svelte';
  import { afterChange } from '../lib/refresh.svelte';
  import Icon from '../components/Icon.svelte';
  import type { Blocker, Blockers, Drive, MigIssue, MigPreflight, MigProgress, Migration, StopResult } from '../lib/types';

  let source = $state('');
  let target = $state('');
  let targetEdited = $state(false);
  let drives = $state<Drive[]>([]);
  let driveMount = $state('');

  let checking = $state(false);
  let pre = $state<MigPreflight | null>(null);
  let blockers = $state<Blockers | null>(null);
  let scanningBlockers = $state(false);
  let picked = $state<Set<number>>(new Set());
  let includeRelated = $state(true);
  let force = $state(false);
  let stopping = $state(false);
  let stopResults = $state<StopResult[]>([]);

  let confirmed = $state(false);
  let running = $state(false);
  let progress = $state<MigProgress | null>(null);
  let done = $state<Migration | null>(null);
  let inUse = $state(false);
  let error = $state('');

  let history = $state<Migration[]>([]);
  let restoringId = $state<string | null>(null);

  async function loadHistory() {
    try {
      history = await api.migList();
    } catch {
      history = [];
    }
  }

  onMount(async () => {
    try {
      drives = await api.listDrives();
    } catch {
      drives = [];
    }
    await loadHistory();
  });

  // 源目录或目标盘变化时，自动给出建议的目标路径（用户手动改过就不再覆盖）。
  $effect(() => {
    if (!targetEdited) target = suggestTarget(source, driveMount);
  });

  // 其他页面（应用卸载、候选清单）带着路径跳转过来。
  let lastRequest = nav.migrateRequest;
  $effect(() => {
    if (nav.migrateRequest !== lastRequest) {
      lastRequest = nav.migrateRequest;
      source = nav.migrateSource;
      resetResult();
    }
  });

  // 默认选一个与源不同的盘。
  $effect(() => {
    const src = driveOf(source);
    if (drives.length && (!driveMount || driveOf(driveMount) === src)) {
      const other = drives.filter((d) => driveOf(d.mount) !== src).sort((a, b) => b.free - a.free)[0];
      if (other) driveMount = other.mount;
    }
  });

  function resetResult() {
    pre = null;
    blockers = null;
    stopResults = [];
    picked = new Set();
    done = null;
    inUse = false;
    error = '';
    confirmed = false;
  }

  async function check() {
    resetResult();
    checking = true;
    try {
      pre = await api.migPreflight(cleanPath(source), cleanPath(target));
      if (pre.can_proceed || pre.issues.some((i) => i.code !== 'invalid_path' && i.code !== 'source_missing')) {
        await detectBlockers();
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      checking = false;
    }
  }

  async function detectBlockers() {
    scanningBlockers = true;
    try {
      blockers = await api.migBlockers(cleanPath(source));
      picked = new Set(blockers.blockers.filter((b) => !b.protection).map((b) => b.pid));
    } catch {
      blockers = null;
    } finally {
      scanningBlockers = false;
    }
  }

  function toggle(pid: number) {
    const n = new Set(picked);
    n.has(pid) ? n.delete(pid) : n.add(pid);
    picked = n;
  }

  async function stop() {
    stopping = true;
    error = '';
    try {
      stopResults = await api.migStop([...picked], includeRelated, force);
      await detectBlockers();
    } catch (e) {
      error = errorText(e);
    } finally {
      stopping = false;
    }
  }

  async function start() {
    running = true;
    error = '';
    inUse = false;
    progress = null;
    const un = await api.onMigProgress((p) => (progress = p));
    try {
      done = await api.migStart(cleanPath(source), cleanPath(target));
      afterChange(); // C 盘空间立刻释放，树和概览同步
      await loadHistory();
    } catch (e) {
      const code = (e as { code?: string })?.code;
      if (code === 'mig_in_use') {
        inUse = true;
        await detectBlockers();
      }
      error = errorText(e);
      await loadHistory();
    } finally {
      un();
      running = false;
    }
  }

  async function restore(m: Migration) {
    restoringId = m.id;
    error = '';
    progress = null;
    const un = await api.onMigProgress((p) => (progress = p));
    try {
      await api.migRestore(m.id);
      afterChange();
    } catch (e) {
      error = errorText(e);
    } finally {
      un();
      restoringId = null;
      await loadHistory();
    }
  }

  const hasErrors = $derived(pre?.issues.some((i) => i.severity === 'error') ?? false);
  const unprotected = $derived(blockers?.blockers.filter((b) => !b.protection) ?? []);

  function issueText(i: MigIssue): string {
    const space = i.code === 'not_enough_space' ? parseSpace(i.detail) : null;
    const params: Record<string, string> = { detail: i.detail ?? '' };
    if (space) {
      params.need = formatSize(space.need);
      params.have = formatSize(space.have);
    }
    return t(`mig.issue.${i.code}`, params);
  }

  const date = (secs: number) => new Date(secs * 1000).toLocaleDateString(i18n.locale === 'zh' ? 'zh-CN' : 'en-US');
  const pct = $derived(progress ? percent(progress.done, progress.total) : 0);
  const nameOf = (b: Blocker) => b.name;
</script>

<h1>{t('mig.title')}</h1>
<p class="muted lead">{t('mig.subtitle')}</p>

{#if error}
  <div class="error" role="alert">{error}</div>
{/if}

<section class="card form">
  <label class="field">
    <span class="muted">{t('mig.source')}</span>
    <input type="text" bind:value={source} placeholder={t('mig.sourcePlaceholder')} spellcheck="false" disabled={running} oninput={resetResult} />
  </label>
  <div class="row two">
    <label class="field">
      <span class="muted">{t('mig.drive')}</span>
      <select bind:value={driveMount} disabled={running} onchange={() => (targetEdited = false)}>
        {#each drives.filter((d) => driveOf(d.mount) !== driveOf(source)) as d (d.mount)}
          <option value={d.mount}>{d.mount} {d.name} · {formatSize(d.free)}</option>
        {/each}
      </select>
    </label>
    <label class="field grow">
      <span class="muted">{t('mig.target')}</span>
      <input type="text" bind:value={target} spellcheck="false" disabled={running} oninput={() => { targetEdited = true; resetResult(); }} />
    </label>
  </div>
  <p class="muted small">{t('mig.targetHint')}</p>
  <div class="row"><span class="grow"></span>
    <button class="primary" onclick={check} disabled={!source.trim() || !target.trim() || checking || running}>
      {checking ? t('mig.checking') : t('mig.check')}
    </button>
  </div>
</section>

{#if pre}
  <section class="card block">
    <div class="row head">
      <Icon kind="folder" size={20} />
      <strong class="grow">{cleanPath(source)}</strong>
      <span class="num">{t('mig.size', { size: formatSize(pre.size), files: pre.files.toLocaleString() })}</span>
    </div>
    {#if pre.source_volume && pre.target_volume}
      <p class="muted small">{t('mig.volumes', { from: pre.source_volume, to: pre.target_volume, free: pre.target_free !== null ? formatSize(pre.target_free) : '?' })}</p>
    {/if}
    {#if pre.issues.length}
      <ul class="issues">
        {#each pre.issues as i}
          <li class={i.severity}><span class="badge {i.severity === 'error' ? 'high' : 'medium'}">{i.severity === 'error' ? '✕' : '!'}</span>{issueText(i)}</li>
        {/each}
      </ul>
    {/if}
    <p class={hasErrors ? 'error' : 'okmsg'}>{hasErrors ? t('mig.cannotGo') : t('mig.canGo')}</p>
  </section>
{/if}

{#if inUse}
  <div class="note" role="alert"><strong>{t('mig.inUseTitle')}</strong><br />{t('mig.inUseBody')}</div>
{/if}

{#if pre && (blockers || scanningBlockers)}
  <section class="card block">
    <div class="row">
      <h2 class="grow">{t('mig.blockersTitle')}</h2>
      <button onclick={detectBlockers} disabled={scanningBlockers || stopping}>{scanningBlockers ? t('mig.checking') : t('mig.recheck')}</button>
    </div>
    {#if blockers}
      <p class="muted small">{t('mig.blockersFiles', { n: blockers.files_checked.toLocaleString() })}{blockers.truncated ? ` · ${t('mig.blockersTruncated')}` : ''}</p>
      {#if blockers.rm_error}<div class="note">{t('mig.rmError', { detail: blockers.rm_error })}</div>{/if}
      {#if blockers.blockers.length === 0}
        <p class="okmsg">{t('mig.blockersNone')}</p>
      {:else}
        <p class="muted small">{t('mig.blockersHint')}</p>
        <ul class="procs">
          {#each blockers.blockers as b (b.pid)}
            <li class:prot={!!b.protection}>
              <label class="row top">
                <input type="checkbox" checked={picked.has(b.pid)} disabled={!!b.protection || stopping} onchange={() => toggle(b.pid)} aria-label={nameOf(b)} />
                <span class="grow">
                  <span class="pn"><Icon kind="exe" size={16} /> {b.name} <span class="muted small num">PID {b.pid}</span></span>
                  {#if b.exe}<span class="mono small muted path" title={b.exe}>{b.exe}</span>{/if}
                  <span class="chips">
                    {#each b.kinds as k}<span class="badge">{t(`mig.kind.${k}`)}</span>{/each}
                    {#if b.service}<span class="badge medium">{t('mig.service', { name: b.service })}</span>{/if}
                    {#if b.protection}<span class="badge high">{t(`mig.protect.${b.protection}`)}</span>{/if}
                  </span>
                  {#if b.related.length}
                    <details>
                      <summary class="small">{t('mig.related', { n: b.related.length })}</summary>
                      <ul class="rel">
                        {#each b.related as r (r.pid)}<li class="small"><span class="mono">{r.name}</span> <span class="muted num">PID {r.pid}</span> <span class="badge">{t(`mig.related.${r.reason}`)}</span></li>{/each}
                      </ul>
                    </details>
                  {/if}
                </span>
              </label>
            </li>
          {/each}
        </ul>

        {#if unprotected.length}
          <div class="stopbar">
            <label class="opt"><input type="checkbox" bind:checked={includeRelated} />{t('mig.includeRelated')}</label>
            <label class="opt"><input type="checkbox" bind:checked={force} />{t('mig.force')}</label>
            {#if force}<p class="note small">{t('mig.forceHint')}</p>{/if}
            <div class="row"><span class="grow"></span>
              <button class={force ? 'danger' : 'primary'} onclick={stop} disabled={picked.size === 0 || stopping}>{stopping ? t('mig.stopping') : t('mig.stop')}</button>
            </div>
          </div>
        {/if}
      {/if}
      {#if stopResults.length}
        <h3 class="sub">{t('mig.stopResult')}</h3>
        <ul class="results">
          {#each stopResults as r}
            <li class="small"><span class="badge {r.status === 'failed' || r.status === 'still_running' || r.status === 'refused' ? 'medium' : 'low'}">{t(`mig.stopStatus.${r.status}`)}</span> <span class="mono">{r.name || '—'}</span> <span class="muted num">PID {r.pid}</span>{#if r.detail} <span class="muted">{r.detail}</span>{/if}</li>
          {/each}
        </ul>
      {/if}
    {/if}
  </section>
{/if}

{#if pre?.can_proceed && !done}
  <section class="card block">
    <h2>{t('mig.howTitle')}</h2>
    <p class="muted">{t('mig.how')}</p>
    {#if running}
      <div role="status" class="prog">
        <p><strong>{progress ? t(`mig.stage.${progress.stage}`) : t('mig.stage.copying')}</strong></p>
        {#if progress?.stage === 'copying' && progress.total > 0}
          <div class="bar"><i style="width:{pct}%"></i></div>
          <p class="muted num small">{t('mig.progress', { done: formatSize(progress.done), total: formatSize(progress.total) })}</p>
        {:else}
          <div class="bar indet"><i></i></div>
        {/if}
        {#if progress?.stage === 'copying' || !progress}
          <button onclick={() => api.migCancel()}>{t('mig.cancel')}</button>
          <p class="muted small">{t('mig.cancelNote')}</p>
        {/if}
      </div>
    {:else}
      <label class="opt confirm"><input type="checkbox" bind:checked={confirmed} />{t('mig.confirm')}</label>
      <div class="row"><span class="grow"></span>
        <button class="danger" disabled={!confirmed} onclick={start}>{t('mig.start')}</button>
      </div>
    {/if}
  </section>
{/if}

{#if done}
  <section class="card block good">
    <h2>{t('mig.doneTitle')}</h2>
    <p>{t('mig.doneBody', { size: formatSize(done.size), target: done.target })}</p>
    {#if done.note}<p class="note small">{done.note}</p>{/if}
  </section>
{/if}

<section class="card block">
  <h2>{t('mig.historyTitle')}</h2>
  {#if history.filter((h) => h.status !== 'restored').length === 0}
    <p class="muted">{t('mig.historyEmpty')}</p>
  {:else}
    <p class="muted small">{t('mig.restoreHint')}</p>
    <ul class="hist">
      {#each history.filter((h) => h.status !== 'restored') as m (m.id)}
        <li>
          <Icon kind="folder" size={18} />
          <span class="grow">
            <span class="mono small path">{m.source}</span>
            <span class="mono small muted path">→ {m.target}</span>
            <span class="small muted">{formatSize(m.size)} · {date(m.created)}</span>
            {#if m.note}<span class="small muted note-line">{m.note}</span>{/if}
            {#if m.old_path}<span class="small note-line">{t('mig.oldLeft', { path: m.old_path })}</span>{/if}
          </span>
          <span class="badge {m.status === 'done' ? 'low' : m.status === 'failed' ? 'medium' : 'high'}">{t(`mig.status.${m.status}`)}</span>
          {#if m.status === 'done'}
            <button onclick={() => restore(m)} disabled={restoringId !== null || running}>{restoringId === m.id ? t('mig.restoring') : t('mig.restore')}</button>
          {/if}
        </li>
      {/each}
    </ul>
    {#if restoringId && progress}
      <div class="bar"><i style="width:{pct}%"></i></div>
    {/if}
  {/if}
</section>

<style>
  .lead { margin-bottom: 16px; }
  .small { font-size: 12.5px; }
  .form, .block { display: flex; flex-direction: column; gap: 10px; margin-top: 14px; }
  .form { margin-top: 0; }
  .field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .two { align-items: flex-end; gap: 12px; }
  .head { gap: 10px; }
  .issues { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
  .issues li { display: flex; gap: 8px; align-items: flex-start; }
  .issues li.warning { color: var(--warn); }
  .okmsg { color: var(--ok); }
  .procs { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  .procs li { padding: 8px 10px; border: 1px solid var(--border); border-radius: 8px; }
  .procs li.prot { background: var(--surface-2); }
  .row.top { align-items: flex-start; gap: 10px; }
  .pn { display: flex; align-items: center; gap: 6px; font-weight: 600; }
  .path { display: block; word-break: break-all; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  details { margin-top: 4px; }
  summary { cursor: pointer; color: var(--accent); }
  .rel { list-style: none; margin: 6px 0 0; padding-left: 8px; display: flex; flex-direction: column; gap: 3px; }
  .stopbar { display: flex; flex-direction: column; gap: 8px; padding-top: 10px; border-top: 1px solid var(--border); }
  .opt { display: flex; gap: 10px; align-items: center; }
  .confirm { font-weight: 600; }
  .sub { margin: 6px 0 0; font-size: 13px; color: var(--muted); }
  .results { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  .prog { display: flex; flex-direction: column; gap: 8px; }
  .good { border-color: var(--ok); }
  .hist { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .hist li { display: flex; align-items: flex-start; gap: 10px; padding: 8px 4px; border-top: 1px solid var(--border); }
  .hist li:first-child { border-top: none; }
  .hist .grow { display: flex; flex-direction: column; gap: 2px; }
  .note-line { word-break: break-all; }
  .indet { height: 6px; }
  .indet i { width: 35%; animation: slide 1.2s ease-in-out infinite; }
  @keyframes slide { 0% { margin-left: -35%; } 100% { margin-left: 100%; } }
</style>
