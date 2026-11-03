<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { formatSize } from '../lib/format';
  import { errorText, t } from '../lib/i18n.svelte';
  import { goMigrate } from '../lib/nav.svelte';
  import Icon from '../components/Icon.svelte';
  import { iconKind, type IconKind } from '../lib/fileicon';
  import type { AppInfo, Leftover, LeftoverReport, Leftovers } from '../lib/types';

  type Step = 'list' | 'confirm' | 'force' | 'running' | 'scanning' | 'still' | 'leftovers' | 'deleting' | 'done';

  let step = $state<Step>('list');
  let apps = $state<AppInfo[] | null>(null);
  let error = $state('');
  let current = $state<AppInfo | null>(null);
  let exitCode = $state<number | null>(null);
  let left = $state<Leftovers | null>(null);
  let selected = $state<Set<number>>(new Set());
  let recycle = $state(true);
  let confirmed = $state(false);
  let report = $state<LeftoverReport | null>(null);

  // 列表筛选
  let query = $state('');
  let tab = $state<'all' | 'desktop' | 'store'>('all');
  let sort = $state<'name' | 'size' | 'date' | 'publisher'>('name');

  async function load() {
    error = '';
    apps = null;
    try {
      apps = await api.appsList(true);
    } catch (e) {
      error = errorText(e);
      apps = [];
    }
  }
  onMount(load);

  const shown = $derived.by(() => {
    if (!apps) return [];
    const q = query.trim().toLowerCase();
    const list = apps.filter(
      (a) =>
        (tab === 'all' || a.kind === tab) &&
        (!q || a.name.toLowerCase().includes(q) || (a.publisher ?? '').toLowerCase().includes(q)),
    );
    const by: Record<typeof sort, (a: AppInfo, b: AppInfo) => number> = {
      name: (a, b) => a.name.localeCompare(b.name),
      size: (a, b) => (b.size_kb ?? -1) - (a.size_kb ?? -1),
      date: (a, b) => (b.install_date ?? '').localeCompare(a.install_date ?? ''),
      publisher: (a, b) => (a.publisher ?? '').localeCompare(b.publisher ?? ''),
    };
    return [...list].sort(by[sort]);
  });

  function pick(a: AppInfo, forced: boolean) {
    current = a;
    error = '';
    step = forced ? 'force' : 'confirm';
  }

  function backToList() {
    step = 'list';
    current = null;
    left = null;
    report = null;
    error = '';
  }

  async function scan(forced: boolean) {
    if (!current) return;
    step = 'scanning';
    error = '';
    try {
      left = await api.appLeftovers(current.id, forced);
      if (left.still_registered && !forced) {
        step = 'still';
      } else {
        selected = new Set(left.items.filter((i) => i.default_selected).map((i) => i.id));
        confirmed = false;
        step = 'leftovers';
      }
    } catch (e) {
      error = errorText(e);
      step = 'list';
    }
  }

  async function uninstall() {
    if (!current) return;
    step = 'running';
    error = '';
    exitCode = null;
    try {
      const r = await api.appUninstall(current.id, false);
      exitCode = r.exit_code;
      await scan(false);
    } catch (e) {
      error = errorText(e);
      step = 'confirm';
    }
  }

  function toggle(id: number) {
    const n = new Set(selected);
    n.has(id) ? n.delete(id) : n.add(id);
    selected = n;
    confirmed = false;
  }

  const selectedSize = $derived(
    left ? left.items.filter((i) => selected.has(i.id)).reduce((a, i) => a + i.size, 0) : 0,
  );

  async function remove() {
    step = 'deleting';
    error = '';
    try {
      report = await api.appDeleteLeftovers([...selected], recycle);
      step = 'done';
    } catch (e) {
      error = errorText(e);
      step = 'leftovers';
    }
  }

  async function finish() {
    backToList();
    await load();
  }

  /** 说明行：原因 · 值名 · 大小，用统一的分隔符拼起来。 */
  function detail(it: Leftover): string {
    return [
      t(`un.reason.${it.reason}`),
      it.value_name ? t('un.valueName', { name: it.value_name }) : '',
      it.size > 0 ? formatSize(it.size) : '',
    ]
      .filter(Boolean)
      .join(' · ');
  }

  function leftIcon(it: Leftover): IconKind {
    if (it.kind === 'reg_key') return 'regkey';
    if (it.kind === 'reg_value') return 'regvalue';
    return iconKind(it.path.split(/[\\/]/).pop() ?? '', it.kind === 'folder');
  }

  const isFile = (k: string) => k === 'folder' || k === 'file';
  const fileItems = $derived(left?.items.filter((i) => isFile(i.kind)) ?? []);
  const regItems = $derived(left?.items.filter((i) => !isFile(i.kind)) ?? []);
  const regCount = (s: string) => report?.registry.filter((r) => r.status === s).length ?? 0;
  const regProblems = $derived(report?.registry.filter((r) => r.status === 'refused' || r.status === 'failed') ?? []);
</script>

<h1>{t('un.title')}</h1>
<p class="muted lead">{t('un.subtitle')}</p>

{#if error}<div class="error" role="alert">{error}</div>{/if}

{#if step === 'list'}
  <div class="row filters">
    <input type="text" class="grow" placeholder={t('un.search')} bind:value={query} aria-label={t('un.search')} />
    <div class="row seg" role="group">
      {#each [['all', 'un.tab.all'], ['desktop', 'un.tab.desktop'], ['store', 'un.tab.store']] as [k, label]}
        <button class:primary={tab === k} aria-pressed={tab === k} onclick={() => (tab = k as typeof tab)}>{t(label)}</button>
      {/each}
    </div>
    <label class="row sortl"><span class="muted">{t('un.sort')}</span>
      <select bind:value={sort}>
        <option value="name">{t('un.sort.name')}</option>
        <option value="size">{t('un.sort.size')}</option>
        <option value="date">{t('un.sort.date')}</option>
        <option value="publisher">{t('un.sort.publisher')}</option>
      </select>
    </label>
  </div>

  {#if apps === null}
    <p class="muted">{t('un.loading')}</p>
  {:else if shown.length === 0}
    <p class="muted empty">{t('un.empty')}</p>
  {:else}
    <p class="muted small">{t('un.count', { n: shown.length })}</p>
    <ul class="apps">
      {#each shown as a (a.id)}
        <li class="card app">
          <div class="grow">
            <div class="nm">{a.name}{#if a.kind === 'store'}<span class="badge">{t('un.store')}</span>{/if}</div>
            <div class="muted meta">
              {[a.version, a.publisher, a.install_date].filter(Boolean).join(' · ')}
            </div>
          </div>
          <span class="muted num size">{a.size_kb !== null ? formatSize(a.size_kb * 1024) : ''}</span>
          {#if a.can_uninstall}
            <button class="primary" onclick={() => pick(a, false)}>{t('un.uninstall')}</button>
          {:else}
            <span class="muted small">{t('un.noInstaller')}</span>
          {/if}
          {#if a.kind === 'desktop' && a.install_location}
            <button onclick={() => goMigrate(a.install_location!)}>{t('un.migrate')}</button>
          {/if}
          {#if a.kind === 'desktop'}<button onclick={() => pick(a, true)}>{t('un.force')}</button>{/if}
        </li>
      {/each}
    </ul>
  {/if}
{:else if step === 'confirm' && current}
  <div class="card panel">
    <h2>{t('un.confirmTitle', { name: current.name })}</h2>
    {#if current.kind === 'store'}
      <p>{t('un.willRunStore')}</p>
    {:else}
      <p>{t('un.willRun')}</p>
      <pre class="mono cmd">{current.uninstall_command}</pre>
    {/if}
    <p class="muted">{t('un.afterNote')}</p>
    <div class="row"><span class="grow"></span>
      <button onclick={backToList}>{t('un.cancel')}</button>
      <button class="danger" onclick={uninstall}>{t('un.run')}</button>
    </div>
  </div>
{:else if step === 'force' && current}
  <div class="card panel">
    <h2>{t('un.forceTitle', { name: current.name })}</h2>
    <p class="note">{t('un.forceNote')}</p>
    {#if current.install_location}<p class="mono small">{t('un.installDir', { path: current.install_location })}</p>{/if}
    <div class="row"><span class="grow"></span>
      <button onclick={backToList}>{t('un.cancel')}</button>
      <button class="danger" onclick={() => scan(true)}>{t('un.forceGo')}</button>
    </div>
  </div>
{:else if step === 'running'}
  <div class="card panel" role="status">
    <h2>{t('un.running')}</h2>
    <p class="muted">{t('un.runningHint')}</p>
    <div class="bar indet"><i></i></div>
  </div>
{:else if step === 'scanning'}
  <div class="card panel" role="status">
    {#if exitCode !== null}<p class="muted">{t('un.exitCode', { code: exitCode })}</p>{/if}
    <h2>{t('un.scanning')}</h2>
    <p class="muted">{t('un.scanningHint')}</p>
    <div class="bar indet"><i></i></div>
  </div>
{:else if step === 'still' && current}
  <div class="card panel">
    {#if exitCode !== null}<p class="muted">{t('un.exitCode', { code: exitCode })}</p>{/if}
    <h2>{t('un.stillTitle')}</h2>
    <p class="note">{t('un.stillBody')}</p>
    <div class="row"><button onclick={backToList}>{t('un.back')}</button><span class="grow"></span>
      <button onclick={() => scan(false)}>{t('un.recheck')}</button>
      <button class="danger" onclick={() => scan(true)}>{t('un.forceInstead')}</button>
    </div>
  </div>
{:else if (step === 'leftovers' || step === 'deleting') && left && current}
  <div class="card panel">
    <h2>{t('un.leftTitle')} · {current.name}</h2>
    {#if left.install_dir}<p class="mono small muted">{t('un.installDir', { path: left.install_dir })}</p>{/if}

    {#if left.items.length === 0}
      <p class="empty">{t('un.leftNone')}</p>
      <div class="row"><span class="grow"></span><button class="primary" onclick={finish}>{t('un.again')}</button></div>
    {:else}
      <p class="muted num">{t('un.leftSummary', { n: left.items.length, sel: selected.size, size: formatSize(selectedSize) })}</p>
      <p class="muted small">{t('un.confHint')}</p>
      <div class="row small-btns">
        <button onclick={() => (selected = new Set(left!.items.filter((i) => i.default_selected).map((i) => i.id)))}>{t('un.selectHigh')}</button>
        <button onclick={() => (selected = new Set(left!.items.map((i) => i.id)))}>{t('un.selectAll')}</button>
        <button onclick={() => (selected = new Set())}>{t('un.selectNone')}</button>
      </div>

      {#each [[fileItems, 'un.group.files'], [regItems, 'un.group.registry']] as [group, label]}
        {#if (group as typeof fileItems).length}
          <h3>{t(label as string)}</h3>
          <ul class="left">
            {#each group as typeof fileItems as it (it.id)}
              <li>
                <label class="row">
                  <input type="checkbox" checked={selected.has(it.id)} disabled={step === 'deleting'} onchange={() => toggle(it.id)} aria-label={it.path} />
                  <Icon kind={leftIcon(it)} />
                  <span class="grow">
                    <span class="mono path" title={it.path}>{it.path}</span>
                    <span class="muted small">{detail(it)}</span>
                  </span>
                  <span class="badge {it.confidence === 'high' ? 'low' : 'medium'}">{t(`un.conf.${it.confidence}`)}</span>
                </label>
              </li>
            {/each}
          </ul>
        {/if}
      {/each}

      <div class="opts">
        <label class="opt"><input type="checkbox" bind:checked={recycle} />{t('un.recycle')}</label>
        <p class="muted small">{t('un.backupNote')}</p>
        <label class="opt confirm"><input type="checkbox" bind:checked={confirmed} />{t('un.confirm')}</label>
      </div>
      <div class="row"><button onclick={backToList} disabled={step === 'deleting'}>{t('un.back')}</button><span class="grow"></span>
        <button class="danger" disabled={selected.size === 0 || !confirmed || step === 'deleting'} onclick={remove}>
          {step === 'deleting' ? t('un.deleting') : t('un.delete')}
        </button>
      </div>
    {/if}
  </div>
{:else if step === 'done' && report}
  <div class="card panel">
    <h2>{t('un.doneTitle')}</h2>
    <p class="num big">{t('un.doneFiles', { size: formatSize(report.files.freed_bytes), deleted: report.files.deleted, recycled: report.files.recycled })}</p>
    {#if report.files.recycled_bytes > 0}<p class="note">{t('report.recycled', { size: formatSize(report.files.recycled_bytes) })}</p>{/if}
    <p class="muted num">{t('un.doneRegistry', { deleted: regCount('deleted'), missing: regCount('missing'), refused: regCount('refused'), failed: regCount('failed') })}</p>
    {#if report.backup_file}
      <p class="note"><span class="mono">{t('un.backupFile', { path: report.backup_file })}</span><br />{t('un.backupRestore')}</p>
    {:else}
      <p class="muted small">{t('un.noBackup')}</p>
    {/if}
    {#if regProblems.length || report.files.problems.length}
      <h3>{t('un.problems')}</h3>
      <ul class="left">
        {#each regProblems as r}
          <li><span class="badge {r.status === 'failed' ? 'high' : 'medium'}">{t(`un.status.${r.status}`)}</span> <span class="mono small">{r.path}{r.value_name ? ` :: ${r.value_name}` : ''}</span>{#if r.detail}<div class="muted small">{r.detail}</div>{/if}</li>
        {/each}
        {#each report.files.problems as p}
          <li><span class="badge {p.status === 'failed' ? 'high' : 'medium'}">{t(`report.status.${p.status}`)}</span> <span class="mono small">{p.path}</span><div class="muted small">{p.detail}</div></li>
        {/each}
      </ul>
    {/if}
    <div class="row"><span class="grow"></span><button class="primary" onclick={finish}>{t('un.again')}</button></div>
  </div>
{/if}

<style>
  .lead { margin-bottom: 16px; }
  .filters { gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
  .seg { gap: 0; }
  .seg button:first-child { border-radius: 8px 0 0 8px; }
  .seg button:last-child { border-radius: 0 8px 8px 0; }
  .seg button:not(:first-child) { margin-left: -1px; border-radius: 0; }
  .seg button:last-child { border-radius: 0 8px 8px 0; }
  .sortl { gap: 6px; }
  .small { font-size: 12.5px; }
  .empty { padding: 18px 0; }
  .apps { list-style: none; margin: 8px 0 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .app { display: flex; align-items: center; gap: 12px; padding: 12px 14px; }
  .nm { font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .meta { font-size: 12.5px; margin-top: 2px; }
  .size { min-width: 70px; text-align: right; font-size: 12.5px; }
  .panel { display: flex; flex-direction: column; gap: 12px; }
  .panel h3 { margin: 6px 0 0; font-size: 13px; color: var(--muted); }
  .cmd { background: var(--surface-2); border-radius: 8px; padding: 10px 12px; margin: 0; white-space: pre-wrap; word-break: break-all; }
  .big { font-size: 16px; font-weight: 600; }
  .small-btns { gap: 8px; }
  .left { list-style: none; margin: 4px 0 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
  .left li { padding: 6px 8px; border-radius: 6px; }
  .left li:hover { background: var(--surface-2); }
  .left label { cursor: pointer; align-items: flex-start; gap: 8px; }
  .path { display: block; word-break: break-all; }
  .opts { display: flex; flex-direction: column; gap: 8px; padding-top: 10px; border-top: 1px solid var(--border); }
  .opt { display: flex; gap: 10px; align-items: center; }
  .confirm { font-weight: 600; }
  .indet { height: 6px; }
  .indet i { width: 35%; animation: slide 1.2s ease-in-out infinite; }
  @keyframes slide { 0% { margin-left: -35%; } 100% { margin-left: 100%; } }
</style>
