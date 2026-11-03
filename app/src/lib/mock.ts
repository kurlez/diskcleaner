// 仅用于在普通浏览器里预览/截图界面，不会进入发布版。
import type { Api, AppInfo, Child, Leftover, CleanProgress, DupGroup, DupProgress, DupSummary, PlanSummary, Report, Rule, ScanProgress, Settings } from './types';

const GB = 1024 ** 3;
const MB = 1024 ** 2;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const tree: Record<string, Child[]> = {
  '': [
    { name: 'Users', size: 182 * GB, is_dir: true, file_count: 412_300 },
    { name: 'Windows', size: 61 * GB, is_dir: true, file_count: 301_220 },
    { name: 'Program Files', size: 54 * GB, is_dir: true, file_count: 118_004 },
    { name: 'ProgramData', size: 9 * GB, is_dir: true, file_count: 20_118 },
    { name: 'pagefile.sys', size: 6 * GB, is_dir: false, file_count: 1 },
  ],
  Users: [
    { name: 'alice', size: 181 * GB, is_dir: true, file_count: 410_000 },
    { name: 'Public', size: 1 * GB, is_dir: true, file_count: 2_300 },
  ],
  'Users\u0000alice': [
    { name: 'AppData', size: 96 * GB, is_dir: true, file_count: 250_000 },
    { name: 'Videos', size: 60 * GB, is_dir: true, file_count: 310 },
    { name: 'Documents', size: 25 * GB, is_dir: true, file_count: 9_800 },
  ],
};

let exclusions: string[] = ['D:\\Projects\\keep'];
let cancelScan = false;
let cancelClean = false;
const listeners = { scan: new Set<(p: ScanProgress) => void>(), clean: new Set<(p: CleanProgress) => void>(), dup: new Set<(p: DupProgress) => void>() };
let cancelDup = false;

const apps: AppInfo[] = [
  { id: 0, name: '7-Zip 23.01 (x64)', version: '23.01', publisher: 'Igor Pavlov', install_date: '2024-02-11', size_kb: 5_400, install_location: 'C:\\Program Files\\7-Zip', kind: 'desktop', can_uninstall: true, uninstall_command: '"C:\\Program Files\\7-Zip\\Uninstall.exe"' },
  { id: 1, name: 'Adobe Acrobat Reader', version: '24.002', publisher: 'Adobe', install_date: '2024-05-02', size_kb: 612_000, install_location: 'C:\\Program Files\\Adobe\\Acrobat Reader', kind: 'desktop', can_uninstall: true, uninstall_command: 'MsiExec.exe /X{AC76BA86-7AD7-1033-7B44-AC0F074E4100}' },
  { id: 2, name: 'Foo Editor', version: '2.1', publisher: 'Acme Inc.', install_date: '2023-11-20', size_kb: 148_000, install_location: 'C:\\Program Files\\Foo Editor', kind: 'desktop', can_uninstall: true, uninstall_command: '"C:\\Program Files\\Foo Editor\\unins000.exe" /SILENT' },
  { id: 3, name: 'Old Broken Tool', version: '0.9', publisher: 'Legacy Soft', install_date: '2019-03-14', size_kb: 12_000, install_location: null, kind: 'desktop', can_uninstall: false, uninstall_command: null },
  { id: 4, name: 'Visual Studio Code', version: '1.95', publisher: 'Microsoft Corporation', install_date: '2024-10-30', size_kb: 390_000, install_location: 'C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code', kind: 'desktop', can_uninstall: true, uninstall_command: '"C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code\\unins000.exe"' },
  { id: 5, name: 'Contoso.Notes', version: '1.0.0.0', publisher: 'CN=Contoso', install_date: null, size_kb: null, install_location: null, kind: 'store', can_uninstall: true, uninstall_command: null },
];
let uninstalledFoo = false;
const leftoverSample: Leftover[] = [
  { id: 0, kind: 'folder', path: 'C:\\Program Files\\Foo Editor', value_name: null, confidence: 'high', reason: 'install_location', size: 148 * MB, files: 1_204, default_selected: true },
  { id: 1, kind: 'folder', path: 'C:\\Users\\alice\\AppData\\Roaming\\FooEditor', value_name: null, confidence: 'high', reason: 'name_match', size: 12 * MB, files: 88, default_selected: true },
  { id: 2, kind: 'folder', path: 'C:\\ProgramData\\Foo', value_name: null, confidence: 'medium', reason: 'name_match', size: 2 * MB, files: 6, default_selected: false },
  { id: 3, kind: 'file', path: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Foo Editor.lnk', value_name: null, confidence: 'high', reason: 'shortcut', size: 1_200, files: 1, default_selected: true },
  { id: 4, kind: 'reg_key', path: 'HKLM\\SOFTWARE\\Acme\\Foo Editor', value_name: null, confidence: 'high', reason: 'name_match', size: 0, files: 0, default_selected: true },
  { id: 5, kind: 'reg_key', path: 'HKLM\\SOFTWARE\\Classes\\CLSID\\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}', value_name: null, confidence: 'high', reason: 'com_registration', size: 0, files: 0, default_selected: true },
  { id: 6, kind: 'reg_value', path: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', value_name: 'FooEditorTray', confidence: 'high', reason: 'auto_run', size: 0, files: 0, default_selected: true },
  { id: 7, kind: 'reg_key', path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\FooUpdater', value_name: null, confidence: 'medium', reason: 'stale_service', size: 0, files: 0, default_selected: false },
];

const t0 = 1_700_000_000;
let dupGroups: DupGroup[] = [
  { id: 0, size: 1_450 * MB, wasted: 2_900 * MB, keep: 0, files: [
    { path: 'D:\\Videos\\trip-2024.mp4', modified: t0 },
    { path: 'D:\\Backup\\old\\trip-2024 (1).mp4', modified: t0 + 86400 * 40 },
    { path: 'D:\\Downloads\\trip-2024.mp4', modified: t0 + 86400 * 90 } ] },
  { id: 1, size: 210 * MB, wasted: 210 * MB, keep: 1, files: [
    { path: 'D:\\Projects\\assets\\texture-pack.zip', modified: t0 + 5000 },
    { path: 'D:\\Downloads\\texture-pack.zip', modified: t0 } ] },
  { id: 2, size: 12 * MB, wasted: 24 * MB, keep: 0, files: [
    { path: 'D:\\Docs\\report.pdf', modified: t0 },
    { path: 'D:\\Docs\\archive\\report-final.pdf', modified: t0 + 100 },
    { path: 'D:\\Desktop\\report.pdf', modified: t0 + 200 } ] },
];
const dupSummary = (): DupSummary => ({ groups: dupGroups, hidden_groups: 0, total_wasted: dupGroups.reduce((a, g) => a + g.wasted, 0), scanned_files: 48_213, errors: 2, cancelled: false });

const rules: Rule[] = [
  ['user_temp', 'low', true], ['system_temp', 'low', true], ['thumbnail_cache', 'low', true],
  ['crash_dumps', 'low', true], ['delivery_optimization', 'low', true], ['old_logs', 'low', true],
  ['browser_cache', 'low', true], ['windows_update_cache', 'medium', false], ['dev_caches', 'medium', false],
].map(([id, risk, d]) => ({ id: id as string, risk: risk as Rule['risk'], default_selected: d as boolean, disposal: 'permanent' }));

export const mockApi: Api = {
  async listDrives() {
    await sleep(150);
    return [
      { mount: 'C:\\', name: 'Windows', fs: 'NTFS', total: 476 * GB, free: 38 * GB },
      { mount: 'D:\\', name: 'Data', fs: 'NTFS', total: 931 * GB, free: 612 * GB },
    ];
  },
  async scanStart(path) {
    cancelScan = false;
    let files = 0;
    for (let i = 1; i <= 12 && !cancelScan; i++) {
      await sleep(120);
      files += 21_000;
      listeners.scan.forEach((cb) => cb({ files, dirs: i * 1900, bytes: i * 14 * GB }));
    }
    return {
      method: 'mft', fallback: null,
      root: path, total_size: 312 * GB, file_count: 852_000, skipped: 37, cancelled: cancelScan,
      top_files: [
        { path: 'C:\\Users\\alice\\Videos\\holiday-2025.mp4', size: 18 * GB },
        { path: 'C:\\pagefile.sys', size: 6 * GB },
        { path: 'C:\\Users\\alice\\AppData\\Local\\Docker\\wsl\\data\\ext4.vhdx', size: 5 * GB + 300 * MB },
        { path: 'C:\\Windows\\SoftwareDistribution\\Download\\a1b2.cab', size: 1 * GB + 80 * MB },
      ],
    };
  },
  async scanCancel() { cancelScan = true; },
  async scanChildren(parts) {
    await sleep(80);
    return { items: tree[parts.join('\u0000')] ?? [], hidden: 0 };
  },
  async reveal() {},
  async rulesList() { return rules; },
  async planBuild(ids) {
    await sleep(700);
    const sizes: Record<string, number> = {
      user_temp: 3 * GB, system_temp: 410 * MB, thumbnail_cache: 220 * MB, crash_dumps: 1 * GB,
      delivery_optimization: 2 * GB, old_logs: 180 * MB, browser_cache: 4 * GB + 512 * MB,
      windows_update_cache: 5 * GB, dev_caches: 7 * GB,
    };
    const by_rule = ids.map((id) => ({ rule_id: id, size: sizes[id] ?? 0, files: Math.round((sizes[id] ?? 0) / 90_000) }));
    const plan: PlanSummary = {
      by_rule, total_size: by_rule.reduce((a, r) => a + r.size, 0), total_files: by_rule.reduce((a, r) => a + r.files, 0),
      item_count: 214,
      skipped: [{ reason: 'too_new', count: 12 }, { reason: 'reparse_point', count: 2 }, { reason: 'protected_inside', count: 1 }],
      items: by_rule.slice(0, 6).map((r) => ({
        rule_id: r.rule_id, size: Math.round(r.size / 3), is_dir: true,
        path: `C:\\Users\\alice\\AppData\\Local\\Temp\\${r.rule_id}-cache`,
      })),
      cancelled: false,
    };
    return plan;
  },
  async planDiscard() {},
  async planExecute(dryRun, recycle) {
    cancelClean = false;
    for (let i = 1; i <= 10 && !cancelClean; i++) {
      await sleep(150);
      listeners.clean.forEach((cb) => cb({ done: i * 21, total: 214 }));
    }
    const rep: Report = {
      dry_run: dryRun, freed_bytes: dryRun || recycle ? 0 : 9 * GB, recycled_bytes: !dryRun && recycle ? 9 * GB : 0,
      deleted: dryRun || recycle ? 0 : 210, recycled: !dryRun && recycle ? 210 : 0, would_delete: dryRun ? 214 : 0,
      failed: dryRun ? 0 : 3, refused: 1, cancelled: cancelClean, service_errors: [],
      problems: dryRun ? [] : [
        { rule_id: 'user_temp', path: 'C:\\Users\\alice\\AppData\\Local\\Temp\\in-use.tmp', status: 'failed', detail: 'The process cannot access the file because it is being used by another process. (os error 32)' },
        { rule_id: 'crash_dumps', path: 'C:\\Windows\\MEMORY.DMP', status: 'refused', detail: 'path is now a link or cloud placeholder' },
      ],
      journal_path: 'C:\\Users\\alice\\AppData\\Roaming\\com.kurlez.diskcleaner\\journal.jsonl',
    };
    return rep;
  },
  async cleanCancel() { cancelClean = true; },
  async settingsGet(): Promise<Settings> { return { exclusions }; },
  async settingsSetExclusions(list) {
    if (list.some((p) => !/^[A-Za-z]:\\/.test(p))) throw { code: 'invalid_exclusion', detail: list.find((p) => !/^[A-Za-z]:\\/.test(p)) };
    exclusions = list;
    return { exclusions };
  },
  async dupScan() {
    cancelDup = false;
    for (const [phase, n] of [['walking', 4], ['partial', 3], ['full', 3]] as const) {
      for (let i = 1; i <= n && !cancelDup; i++) {
        await sleep(150);
        listeners.dup.forEach((cb) => cb({ phase, done: phase === 'walking' ? i * 12_000 : i * 40, total: phase === 'walking' ? 0 : n * 40 }));
      }
    }
    return dupSummary();
  },
  async dupCancel() { cancelDup = true; },
  async dupCurrent() { return dupSummary(); },
  async dupDelete(sel, recycle) {
    await sleep(400);
    const drop = new Set(sel.map((s) => `${s.group}:${s.file}`));
    const freed = sel.reduce((a, s) => a + dupGroups[s.group].size, 0);
    dupGroups = dupGroups
      .map((g) => ({ ...g, files: g.files.filter((_, i) => !drop.has(`${g.id}:${i}`)) }))
      .filter((g) => g.files.length > 1)
      .map((g) => ({ ...g, keep: 0, wasted: g.size * (g.files.length - 1) }));
    return {
      dry_run: false, freed_bytes: recycle ? 0 : freed, recycled_bytes: recycle ? freed : 0,
      deleted: recycle ? 0 : sel.length, recycled: recycle ? sel.length : 0, would_delete: 0,
      failed: 0, refused: 0, cancelled: false, problems: [], service_errors: [],
      journal_path: 'C:\\Users\\alice\\AppData\\Roaming\\com.kurlez.diskcleaner\\journal.jsonl',
    };
  },
  async sysList() {
    await sleep(250);
    return [
      { id: 'recycle_bin', risk: 'medium' as const, estimate: 2 * GB + 300 * MB },
      { id: 'hibernation', risk: 'medium' as const, estimate: 6 * GB },
      { id: 'component_store', risk: 'low' as const, estimate: null },
      { id: 'windows_old', risk: 'high' as const, estimate: 18 * GB },
      { id: 'shadow_copy', risk: 'high' as const, estimate: null },
    ];
  },
  async sysRun(id) {
    await sleep(900);
    if (id === 'shadow_copy') throw { code: 'sys_failed', detail: 'command_failed: vssadmin.exe exited with 1: No items found that satisfy the query.' };
    return { id, free_before: 38 * GB, free_after: 44 * GB, output: '' };
  },
  async candResolve(items) {
    await sleep(120);
    return items.map((parts) => ({
      path: ['C:', ...parts].join('\\'),
      is_dir: !/\.[a-z0-9]+$/i.test(parts[parts.length - 1] ?? ''),
      size: 150 * MB, files: 12, exists: true, is_link: false,
    }));
  },
  async candDelete(items, recycle) {
    await sleep(600);
    return {
      dry_run: false, freed_bytes: recycle ? 0 : items.length * 150 * MB, recycled_bytes: recycle ? items.length * 150 * MB : 0,
      deleted: recycle ? 0 : items.length, recycled: recycle ? items.length : 0, would_delete: 0,
      failed: 0, refused: 0, cancelled: false, problems: [], service_errors: [],
      journal_path: 'C:\\Users\\alice\\AppData\\Roaming\\com.kurlez.diskcleaner\\journal.jsonl',
    };
  },
  async appsList(includeStore) {
    await sleep(300);
    return apps.filter((a) => includeStore || a.kind === 'desktop');
  },
  async appUninstall(id) {
    await sleep(1800);
    if (id === 2) uninstalledFoo = true;
    return { exit_code: 0, still_registered: id !== 2 };
  },
  async appLeftovers(id, forced) {
    await sleep(900);
    if (id !== 2) {
      // 其他程序：未强制时仍登记着；强制时给出它自己的登记项和目录。
      if (!forced) return { items: [], still_registered: true, install_dir: null, total_size: 0 };
      const items = [
        { id: 0, kind: 'folder' as const, path: 'C:\\Program Files\\Legacy Soft\\Old Broken Tool', value_name: null, confidence: 'high' as const, reason: 'name_match', size: 12 * MB, files: 40, default_selected: true },
        { id: 1, kind: 'reg_key' as const, path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OldBrokenTool', value_name: null, confidence: 'high' as const, reason: 'uninstall_entry', size: 0, files: 0, default_selected: true },
      ];
      return { items, still_registered: true, install_dir: null, total_size: 12 * MB };
    }
    if (!uninstalledFoo && !forced) return { items: [], still_registered: true, install_dir: null, total_size: 0 };
    const items = forced
      ? [...leftoverSample, { id: 8, kind: 'reg_key' as const, path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Foo Editor', value_name: null, confidence: 'high' as const, reason: 'uninstall_entry', size: 0, files: 0, default_selected: true }]
      : leftoverSample;
    return { items, still_registered: !uninstalledFoo, install_dir: 'C:\\Program Files\\Foo Editor', total_size: items.reduce((a, i) => a + i.size, 0) };
  },
  async appDeleteLeftovers(selected, recycle) {
    await sleep(700);
    const chosen = leftoverSample.filter((i) => selected.includes(i.id));
    const files = chosen.filter((i) => i.kind === 'folder' || i.kind === 'file');
    const freed = files.reduce((a, i) => a + i.size, 0);
    return {
      registry: chosen.filter((i) => i.kind.startsWith('reg')).map((i) => ({
        path: i.path, value_name: i.value_name,
        status: i.reason === 'stale_service' ? 'refused' as const : 'deleted' as const,
        detail: i.reason === 'stale_service' ? 'changed since the scan' : null,
      })),
      files: {
        dry_run: false, freed_bytes: recycle ? 0 : freed, recycled_bytes: recycle ? freed : 0,
        deleted: recycle ? 0 : files.length, recycled: recycle ? files.length : 0, would_delete: 0,
        failed: 0, refused: 0, cancelled: false, problems: [], service_errors: [], journal_path: 'C:\\Users\\alice\\AppData\\Roaming\\com.kurlez.diskcleaner\\journal.jsonl',
      },
      backup_file: 'C:\\Users\\alice\\AppData\\Roaming\\com.kurlez.diskcleaner\\registry-backups\\20241103-120000-Foo_Editor.reg',
    };
  },
  async onDupProgress(cb) { listeners.dup.add(cb); return () => listeners.dup.delete(cb); },
  async onScanProgress(cb) { listeners.scan.add(cb); return () => listeners.scan.delete(cb); },
  async onCleanProgress(cb) { listeners.clean.add(cb); return () => listeners.clean.delete(cb); },
};
