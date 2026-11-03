<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { formatSize, percent } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import SystemTools from '../components/SystemTools.svelte';
  import type { CleanProgress, PlanSummary, Report, Rule } from '../lib/types';

  type Step = 'select' | 'preview' | 'running' | 'report';

  let step = $state<Step>('select');
  let rules = $state<Rule[]>([]);
  let selected = $state<Record<string, boolean>>({});
  let plan = $state<PlanSummary | null>(null);
  let report = $state<Report | null>(null);
  let progress = $state<CleanProgress | null>(null);
  let exclusionCount = $state(0);
  let analyzing = $state(false);
  let error = $state('');

  let dryRun = $state(false);
  let recycle = $state(false);
  let confirmed = $state(false);

  const chosen = $derived(rules.filter((r) => selected[r.id]).map((r) => r.id));
  const sortedRules = $derived([...(plan?.by_rule ?? [])].sort((a, b) => b.size - a.size));
  const maxRule = $derived(Math.max(1, ...(plan?.by_rule.map((r) => r.size) ?? [1])));

  onMount(async () => {
    try {
      rules = await api.rulesList();
      selected = Object.fromEntries(rules.map((r) => [r.id, r.default_selected]));
    } catch (e) {
      error = errorText(e);
    }
  });

  async function analyze() {
    analyzing = true;
    error = '';
    try {
      plan = await api.planBuild(chosen);
      exclusionCount = (await api.settingsGet()).exclusions.length;
      confirmed = false;
      step = 'preview';
    } catch (e) {
      error = errorText(e);
    } finally {
      analyzing = false;
    }
  }

  async function back() {
    await api.planDiscard().catch(() => {});
    plan = null;
    step = 'select';
  }

  async function run() {
    step = 'running';
    error = '';
    progress = null;
    const unlisten = await api.onCleanProgress((p) => (progress = p));
    try {
      report = await api.planExecute(dryRun, recycle);
      step = 'report';
    } catch (e) {
      error = errorText(e);
      step = 'select';
      plan = null;
    } finally {
      unlisten();
    }
  }

  function again() {
    report = null;
    plan = null;
    step = 'select';
  }

  const steps: { id: Step; key: string }[] = [
    { id: 'select', key: 'clean.step.select' },
    { id: 'preview', key: 'clean.step.preview' },
    { id: 'report', key: 'clean.step.report' },
  ];
  const stepIndex = $derived(step === 'running' ? 1 : steps.findIndex((s) => s.id === step));
</script>

<h1>{t('clean.title')}</h1>
<p class="muted lead">{t('clean.subtitle')}</p>

<ol class="steps" aria-label="Progress">
  {#each steps as s, i}
    <li class:done={i < stepIndex} class:current={i === stepIndex} aria-current={i === stepIndex ? 'step' : undefined}>
      <span class="dot">{i + 1}</span>{t(s.key)}
    </li>
  {/each}
</ol>

{#if error}<div class="error" role="alert">{error}</div>{/if}

{#if step === 'select'}
  <div class="card list">
    {#each rules as r (r.id)}
      <label class="rule">
        <input type="checkbox" bind:checked={selected[r.id]} />
        <span class="grow">
          <span class="rname">{t(`rule.${r.id}.name`)}</span>
          <span class="muted rdesc">{t(`rule.${r.id}.desc`)}</span>
        </span>
        <span class="badge {r.risk}">{t(`clean.risk.${r.risk}`)}</span>
      </label>
    {/each}
  </div>
  <div class="row foot">
    <span class="muted grow">{t('clean.selected', { n: chosen.length })}</span>
    <button class="primary" disabled={chosen.length === 0 || analyzing} onclick={analyze}>
      {analyzing ? t('clean.analyzing') : t('clean.analyze')}
    </button>
  </div>
  <SystemTools />
{:else if step === 'preview' && plan}
  <div class="card">
    <div class="row head">
      <h2 class="grow">{t('clean.previewTitle')}</h2>
      <strong class="big num">{t('clean.reclaim', { size: formatSize(plan.total_size) })}</strong>
    </div>
    <p class="muted num">{t('clean.summary', { items: plan.item_count.toLocaleString(), files: plan.total_files.toLocaleString() })}</p>

    {#if plan.item_count === 0}
      <p class="empty">{t('clean.nothing')}</p>
    {:else}
      <ul class="rules">
        {#each sortedRules as r (r.rule_id)}
          <li>
            <span class="rn ellipsis">{t(`rule.${r.rule_id}.name`)}</span>
            <span class="bar"><i style="width:{percent(r.size, maxRule)}%"></i></span>
            <span class="num sz">{formatSize(r.size)}</span>
          </li>
        {/each}
      </ul>
    {/if}

    {#if plan.skipped.length}
      <div class="skipped">
        <span class="muted">{t('clean.skippedTitle')}:</span>
        {#each plan.skipped as s}<span class="badge">{t(`skip.${s.reason}`)} · {s.count}</span>{/each}
      </div>
    {/if}
    {#if exclusionCount > 0}<p class="muted small">{t('clean.excludedNote', { n: exclusionCount })}</p>{/if}

    {#if plan.items.length}
      <details>
        <summary>{t('clean.biggest', { n: plan.items.length })}</summary>
        <ul class="items">
          {#each plan.items as it}
            <li><span class="num sz">{formatSize(it.size)}</span><span class="mono ellipsis" title={it.path}>{it.path}</span></li>
          {/each}
        </ul>
      </details>
    {/if}
  </div>

  {#if plan.item_count > 0}
    <div class="card opts">
      <h2>{t('clean.options')}</h2>
      <label class="opt"><input type="checkbox" bind:checked={dryRun} />{t('clean.optDry')}</label>
      <label class="opt"><input type="checkbox" bind:checked={recycle} disabled={dryRun} />
        <span>{t('clean.optRecycle')}<br /><span class="muted small">{t('clean.optRecycleHint')}</span></span>
      </label>
      <label class="opt confirm"><input type="checkbox" bind:checked={confirmed} />{t('clean.confirm')}</label>
    </div>
  {/if}

  <div class="row foot">
    <button onclick={back}>{t('clean.back')}</button>
    <span class="grow"></span>
    {#if plan.item_count > 0}
      <button class={dryRun ? 'primary' : 'danger'} disabled={!confirmed} onclick={run}>
        {dryRun ? t('clean.confirmDry') : t('clean.execute')}
      </button>
    {/if}
  </div>
{:else if step === 'running'}
  <div class="card" role="status">
    <h2>{t('clean.running')}</h2>
    {#if progress}
      <div class="bar"><i style="width:{percent(progress.done, progress.total)}%"></i></div>
      <p class="muted num">{t('clean.progress', { done: progress.done, total: progress.total })}</p>
    {/if}
    <button onclick={() => api.cleanCancel()}>{t('clean.stop')}</button>
  </div>
{:else if step === 'report' && report}
  <div class="card">
    <h2>{report.dry_run ? t('report.dryTitle') : t('report.title')}</h2>
    {#if report.dry_run}
      <p>{t('report.dryNote', { n: report.would_delete })}</p>
    {:else}
      <p class="big num">{t('report.freed', { size: formatSize(report.freed_bytes) })}</p>
      {#if report.recycled_bytes > 0}<p class="note">{t('report.recycled', { size: formatSize(report.recycled_bytes) })}</p>{/if}
      <p class="muted num">{t('report.counts', { deleted: report.deleted, recycled: report.recycled, failed: report.failed, refused: report.refused })}</p>
    {/if}
    {#if report.cancelled}<div class="note">{t('report.cancelled')}</div>{/if}
    {#if report.service_errors.length}
      <div class="note"><strong>{t('report.serviceErrors')}</strong>
        {#each report.service_errors as e}<div class="mono small">{e}</div>{/each}
      </div>
    {/if}

    {#if report.problems.length}
      <h2 class="ph">{t('report.problems')}</h2>
      <ul class="problems">
        {#each report.problems as p}
          <li>
            <span class="badge {p.status === 'failed' ? 'high' : 'medium'}">{t(`report.status.${p.status}`)}</span>
            <span class="mono ellipsis" title={p.path}>{p.path}</span>
            <span class="muted small det" title={p.detail}>{p.detail}</span>
          </li>
        {/each}
      </ul>
    {/if}
    <p class="muted small mono jr">{t('report.journal', { path: report.journal_path })}</p>
  </div>
  <div class="row foot"><span class="grow"></span><button class="primary" onclick={again}>{t('report.again')}</button></div>
{/if}

<style>
  .lead { margin-bottom: 16px; }
  .steps { list-style: none; display: flex; gap: 22px; padding: 0; margin: 0 0 16px; color: var(--muted); }
  .steps li { display: flex; align-items: center; gap: 8px; }
  .steps .dot { width: 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--border); font-size: 12px; }
  .steps li.current { color: var(--text); font-weight: 600; }
  .steps li.current .dot { background: var(--accent); color: var(--accent-text); border-color: transparent; }
  .steps li.done .dot { background: var(--accent-soft); color: var(--accent); }
  .list { padding: 6px; }
  .rule { display: flex; align-items: center; gap: 12px; padding: 10px; border-radius: 8px; cursor: pointer; }
  .rule:hover { background: var(--surface-2); }
  .rname { display: block; font-weight: 600; }
  .rdesc { display: block; font-size: 12.5px; margin-top: 2px; }
  .foot { margin-top: 16px; }
  .head { align-items: baseline; }
  .big { font-size: 18px; font-weight: 700; }
  .small { font-size: 12.5px; }
  .rules { list-style: none; padding: 0; margin: 14px 0 6px; display: flex; flex-direction: column; gap: 8px; }
  .rules li { display: grid; grid-template-columns: minmax(140px, 220px) 1fr 80px; gap: 12px; align-items: center; }
  .sz { text-align: right; }
  .skipped { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 12px; }
  .empty { padding: 18px 0; color: var(--muted); }
  details { margin-top: 12px; }
  summary { cursor: pointer; color: var(--accent); }
  .items { list-style: none; padding: 0; margin: 10px 0 0; display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow: auto; }
  .items li { display: grid; grid-template-columns: 80px 1fr; gap: 8px; }
  .opts { margin-top: 14px; display: flex; flex-direction: column; gap: 10px; }
  .opt { display: flex; gap: 10px; align-items: flex-start; }
  .confirm { padding-top: 8px; border-top: 1px solid var(--border); font-weight: 600; }
  .card + .card { margin-top: 14px; }
  .ph { margin-top: 16px; }
  .jr { margin-top: 14px; word-break: break-all; }
  .problems { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px; }
  .problems li { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 4px 10px; align-items: center; }
  .det { grid-column: 2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
