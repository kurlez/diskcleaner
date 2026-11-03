// 与后端 service.rs 中的 DTO 一一对应。

export type Risk = 'low' | 'medium' | 'high';
export type Disposal = 'recycle' | 'permanent';

export interface Drive { mount: string; name: string; fs: string; total: number; free: number }
export interface FileEntry { path: string; size: number }
export interface ScanSummary {
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
  cancelled: boolean; problems: Problem[]; journal_path: string;
}
export interface ScanProgress { files: number; dirs: number; bytes: number }
export interface CleanProgress { done: number; total: number }
export interface Settings { exclusions: string[] }

export interface ApiError { code: string; detail?: string | null }

export interface Api {
  listDrives(): Promise<Drive[]>;
  scanStart(path: string): Promise<ScanSummary>;
  scanCancel(): Promise<void>;
  scanChildren(parts: string[]): Promise<Children>;
  reveal(parts: string[]): Promise<void>;
  rulesList(): Promise<Rule[]>;
  planBuild(ruleIds: string[]): Promise<PlanSummary>;
  planDiscard(): Promise<void>;
  planExecute(dryRun: boolean, recycle: boolean): Promise<Report>;
  cleanCancel(): Promise<void>;
  settingsGet(): Promise<Settings>;
  settingsSetExclusions(exclusions: string[]): Promise<Settings>;
  onScanProgress(cb: (p: ScanProgress) => void): Promise<() => void>;
  onCleanProgress(cb: (p: CleanProgress) => void): Promise<() => void>;
}
