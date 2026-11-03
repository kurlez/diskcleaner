// 与后端 service.rs 中的 DTO 一一对应。

export type Risk = 'low' | 'medium' | 'high';
export type Disposal = 'recycle' | 'permanent';

export interface Drive { mount: string; name: string; fs: string; total: number; free: number }
export interface FileEntry { path: string; size: number }
export interface ScanSummary {
  method: 'mft' | 'walk'; fallback: string | null;
  root: string; total_size: number; file_count: number; skipped: number;
  cancelled: boolean; top_files: FileEntry[];
}
export interface Child { name: string; size: number; is_dir: boolean; file_count: number }
export interface Children { items: Child[]; hidden: number }
export interface Rule { id: string; risk: Risk; default_selected: boolean; disposal: Disposal }
export interface RuleTotal { rule_id: string; size: number; files: number }
export interface SkipCount { reason: string; count: number }
export interface PlanItem { rule_id: string; path: string; size: number; is_dir: boolean }
export interface PlanSummary {
  by_rule: RuleTotal[]; total_size: number; total_files: number; item_count: number;
  skipped: SkipCount[]; items: PlanItem[]; cancelled: boolean;
}
export interface Problem { rule_id: string; path: string; status: 'failed' | 'refused'; detail: string }
export interface Report {
  dry_run: boolean; freed_bytes: number; recycled_bytes: number; deleted: number;
  recycled: number; would_delete: number; failed: number; refused: number;
  cancelled: boolean; problems: Problem[]; service_errors: string[]; journal_path: string;
}
export interface ScanProgress { files: number; dirs: number; bytes: number }
export interface CleanProgress { done: number; total: number }
export interface Settings { exclusions: string[] }

export interface DupFile { path: string; modified: number }
export interface DupGroup { id: number; size: number; wasted: number; keep: number; files: DupFile[] }
export interface DupSummary {
  groups: DupGroup[]; hidden_groups: number; total_wasted: number;
  scanned_files: number; errors: number; cancelled: boolean;
}
export interface DupProgress { phase: 'walking' | 'partial' | 'full'; done: number; total: number }
export interface DupSelection { group: number; file: number; path?: string }

export interface SysAction { id: string; risk: Risk; estimate: number | null }
export interface SysResult { id: string; free_before: number | null; free_after: number | null; output: string }

export interface AppInfo {
  id: number; name: string; version: string | null; publisher: string | null;
  install_date: string | null; size_kb: number | null; install_location: string | null;
  kind: 'desktop' | 'store'; can_uninstall: boolean; uninstall_command: string | null;
}
export interface UninstallRun { exit_code: number; still_registered: boolean }
export interface Leftover {
  id: number; kind: 'folder' | 'file' | 'reg_key' | 'reg_value'; path: string;
  value_name: string | null; confidence: 'high' | 'medium'; reason: string;
  size: number; files: number; default_selected: boolean;
}
export interface Leftovers { items: Leftover[]; still_registered: boolean; install_dir: string | null; total_size: number }
export interface RegResult { path: string; value_name: string | null; status: 'deleted' | 'missing' | 'refused' | 'failed'; detail: string | null }
export interface LeftoverReport { registry: RegResult[]; files: Report; backup_file: string | null }

export interface CandResolved {
  path: string; is_dir: boolean; size: number; files: number; exists: boolean; is_link: boolean;
}

export interface MigIssue { severity: 'error' | 'warning'; code: string; detail: string | null }
export interface MigPreflight {
  size: number; files: number; issues: MigIssue[]; can_proceed: boolean;
  source_volume: string | null; target_volume: string | null; target_free: number | null;
}
export interface Related { pid: number; name: string; reason: 'descendant' | 'same_folder' }
export interface Blocker {
  pid: number; name: string; exe: string | null; kinds: string[]; service: string | null;
  protection: 'this_app' | 'critical' | 'explorer' | 'service_host' | null; related: Related[];
}
export interface Blockers { blockers: Blocker[]; rm_error: string | null; files_checked: number; truncated: boolean }
export interface StopResult { pid: number; name: string; status: string; detail: string | null }
export interface Migration {
  id: string; source: string; target: string; size: number; files: number; created: number;
  status: 'copying' | 'switching' | 'done' | 'restoring' | 'failed' | 'restored';
  note: string | null; old_path: string | null;
}
export interface MigProgress { stage: 'copying' | 'verifying' | 'switching' | 'cleaning'; done: number; total: number }

export interface ApiError { code: string; detail?: string | null }

export interface Api {
  listDrives(): Promise<Drive[]>;
  scanStart(path: string): Promise<ScanSummary>;
  scanCancel(): Promise<void>;
  scanCurrent(): Promise<ScanSummary>;
  scanChildren(parts: string[]): Promise<Children>;
  reveal(parts: string[]): Promise<void>;
  rulesList(): Promise<Rule[]>;
  planBuild(ruleIds: string[]): Promise<PlanSummary>;
  planDiscard(): Promise<void>;
  planExecute(dryRun: boolean, recycle: boolean): Promise<Report>;
  cleanCancel(): Promise<void>;
  settingsGet(): Promise<Settings>;
  settingsSetExclusions(exclusions: string[]): Promise<Settings>;
  dupScan(path: string, minSizeMb: number): Promise<DupSummary>;
  dupCancel(): Promise<void>;
  dupCurrent(): Promise<DupSummary>;
  dupDelete(selections: DupSelection[], recycle: boolean): Promise<Report>;
  sysList(): Promise<SysAction[]>;
  sysRun(id: string): Promise<SysResult>;
  migPreflight(source: string, target: string): Promise<MigPreflight>;
  migBlockers(dir: string): Promise<Blockers>;
  migStop(pids: number[], includeRelated: boolean, force: boolean): Promise<StopResult[]>;
  migStart(source: string, target: string): Promise<Migration>;
  migCancel(): Promise<void>;
  migList(): Promise<Migration[]>;
  migRestore(id: string): Promise<Migration>;
  onMigProgress(cb: (p: MigProgress) => void): Promise<() => void>;
  candResolve(items: string[][]): Promise<CandResolved[]>;
  candDelete(items: string[][], recycle: boolean): Promise<Report>;
  appsList(includeStore: boolean): Promise<AppInfo[]>;
  appUninstall(id: number, silent: boolean): Promise<UninstallRun>;
  appLeftovers(id: number, forced: boolean): Promise<Leftovers>;
  appDeleteLeftovers(selected: number[], recycle: boolean): Promise<LeftoverReport>;
  onDupProgress(cb: (p: DupProgress) => void): Promise<() => void>;
  onScanProgress(cb: (p: ScanProgress) => void): Promise<() => void>;
  onCleanProgress(cb: (p: CleanProgress) => void): Promise<() => void>;
}
