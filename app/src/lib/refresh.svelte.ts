/**
 * 全局"磁盘内容变了"信号。任何清理、卸载、迁移、还原之后调用 [`afterChange`]，
 * 各视图订阅对应的计数器并立即刷新自己，用户不需要手动重新扫描。
 */
export const refresh = $state({ scan: 0, drives: 0, dups: 0 });

export function afterChange() {
  refresh.scan++;
  refresh.drives++;
  refresh.dups++;
}
