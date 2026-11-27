# 经营备份恢复后的敏感副本清除核验

记录标识和快照引用均为虚构。日期用序列日。清除与隐藏是不同的现有回报类型。 资料均为本地合成记录。

以 Python 3.11.2 运行，无第三方依赖。`records/` 中的 `retention`、`snapshots`、`restores` 对应独立来源。每份材料是 JSON 对象数组，`id` 在同一来源内唯一。报告和观察的时间以各原始记录给出的字段为准。

```sh
python3 -m unittest -v
python3 records_view.py
```

资料入口列出来源、记录标识及条数。通过 `--source` 指定来源，`--offset` 和 `--limit` 限定读取的位置与数量。`--records` 可指定同样结构的其他资料目录。

## 本地审计工具（只读）

`audit.py` 串联三个独立来源，逐副本核对“台账到期/保全 → 快照身份/分区/派生索引 → 挂接/访问/清理再验证回执”，回答三件事：哪些派生副本确已清理、哪些仍有保全依据、备份恢复后要重新执行哪些防御验证。它只读取合成清单与回执，不读取、恢复或删除真实资料。

```sh
python3 audit.py --format text                 # 中文审计报告
python3 audit.py                               # 完整 JSON 结论
python3 audit.py --records 其他资料目录 --as-of 20
python3 audit.py --check                       # 恢复审批门禁：存在未通过审批时退出码 3
python3 audit.py --can-delete att-7,lease-7    # 删除前保全拦截
python3 records_view.py audit --format text    # 同一入口的子命令形式
```

当前随库资料的结论与逐项依据见 [AUDIT.md](./AUDIT.md)，机器可读结果见
[`audit-report.json`](./audit-report.json) / [`audit-report.txt`](./audit-report.txt)。

判定原则（与资料中的字段一一对应）：

- 证明按 **记录身份 + 范围（scope/分区/派生索引）+ 快照代/恢复目标** 匹配；`scope=primary` 的旧证明不覆盖 `index-a` 等派生范围。
- 重建到新目标（`target`，如 `restored-2`）的副本以恢复经办的独立 `checked/pending` 再验证为准；旧清理证明不能自动覆盖新重建副本。
- “隐藏/不可见”类回报不等于“清除”；只有证实的清除类证明才计 `cleaned_verified`。
- 保全以 `hold_until` 指定的身份和期间为限：保全副本禁止删除，也不得因此跳过同盘其他附件；期间届满需台账续期依据。
- 同名不同归属不合并，以跨来源 ID 可核实的归属为准。
- 引用悬空、台账缺分类、缺少哈希/签名等无法核对完整性的情形，写入 `gaps`（采集缺口）与 `pending_scope`（待查范围），不推定为已清理。
- 恢复审批区分 `pending_verification`（少量受影响副本待验证，附 `affected_copies`）、`blocked_reappearance`（到期可访问副本将重现）、`evidence_gap` 与 `generation_verified`（整代恢复通过）。

Python API：`audit.audit(records_dir_or_sources_dict, as_of=None)` 返回完整报告；`build_report(sources, as_of=...)`、`evaluate_restores(...)`、`evaluate_deletion(report, item_ids)` 等同义入口也可从 `records_view` 导入。
