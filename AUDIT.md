# 审计结论：备份恢复后的敏感副本清除核验

本文件是本地只读审计工具对当前 `records/` 合成资料的一次运行结论（基准序列日 **10**，
取来源中最大观察日；可用 `--as-of` 覆盖）。机器可读全文见
[`audit-report.json`](./audit-report.json)，纯文本报告见 [`audit-report.txt`](./audit-report.txt)。

> 工具只读取 `records/*.json` 清单与回执，不读取、恢复或删除任何真实资料。
> “已核实”仅表示回执证据在 **身份 + 范围 + 快照代/恢复目标** 上可匹配；
> 实际字节完整性仍需按第四节清单在恢复后再验证。

## 1. 哪些副本确实已经清理

| 副本 | 身份 | 结论 | 证据 |
| --- | --- | --- | --- |
| 线上主副本 `primary` | `att-7`（人员附件，第 9 日到期） | **已清除并核实** | `clean-1`，第 10 日，`proof=confirmed` 的清除类回报，范围 `primary` 匹配 |
| `backup-1` 内记录副本 | `att-7` | **未清理 / 残留**：清单仍含该身份，无匹配清除证明 | `backup-1.contains` |
| `child-2` 的派生索引 `index-a → att-7` | `att-7` | **未清理 / 残留**：`clean-1` 范围是 `primary`，不覆盖派生索引 | `child-2.derived` |
| 恢复目标 `restored-2` 的 `index-a` | `att-7` | **待实际再验证**：`index-review` 中 `pending: ["index-a"]`；旧证明不能自动覆盖重建副本 | `index-review`、`open-2` |

即：**目前只有 `att-7` 的线上主副本可认定为已清理；没有任何派生索引或备份/恢复副本可认定为“确实已经清理”。**
线上看不到（或访问回执为 `not_approved`）不等于派生副本已清除，重建服务后索引可能令其重现。

## 2. 哪些仍有保全依据

- `lease-7`（租赁档案，`category=lease`）：台账 `keep-1` 载明 `hold_until=37`，基准日 10
  **仍在保全期间**。其 4 个已知副本（主副本、`backup-1`、`child-2`、`restored-2`）均有保全依据，
  **不得删除**；其中 `restored-2` 上的副本已经 `index-review.checked` 核验在位（`held_verified`）。
- 保全只覆盖 `lease-7` 这一指定身份至第 37 日：**不能**据此跳过同盘其他附件（`att-7` 仍须清理核验），
  第 37 日届满后若台账未续期，工具会改判 `hold_period_ended` 并列入待查，而不是自动放行删除。
- 删除前可用保全拦截复核：

  ```sh
  python3 audit.py --can-delete att-7,lease-7,unknown-1
  # lease-7 -> blocked_held；att-7 -> 可在范围匹配+再验证后清理；unknown-1 -> 台账不明，待查
  ```

## 3. 恢复审批：1 个受影响副本待验证，不是整代通过

`restored-2` 实际挂接自 `child-2`（`open-2`）。审批结论：

- `decision = "pending_verification"`（少量受影响副本待验证，**非**整代恢复通过）；
- 受影响副本恰好 **1** 个：`index-a`（派生自已到期的 `att-7`，验证状态 `pending`）；
- 已核验副本：`lease-7`（`checked`，保全在位）；
- 访问状态：`open-2.access = not_approved`，归一为 `blocked`（保护措施，但恢复后必须实测仍然生效）；
- 若已到期副本被回报为 `access=approved/ready`，结论会升级为
  `blocked_reappearance`（已到期可访问副本将重现，直接阻断）；
- 只有当一代内全部副本分别取得“到期→清除再验证 checked / 保全→在位 checked”后，
  才会给出 `generation_verified`（整代恢复通过）。

门禁用法（存在未通过的恢复审批时退出码 `3`，可接入审批流水线）：

```sh
python3 audit.py --check ; echo $?   # 当前资料：3
```

## 4. 一次备份恢复后应重新执行的防御验证

工具为每个恢复目标生成带编号的 `defensive_checks` / `checklist`（当前资料 9 项），要点：

1. **重建副本清除再验证（高）**：在实际挂接目标上，用与读取方/攻击者相同的检索路径验证
   `index-a` 不再解析出 `att-7` 的内容或索引项，并取得新的独立回执；旧 `primary` 证明不抵用。
2. **访问限制实测（高）**：以未授权身份探测，确认 `not_approved` 在服务重建后仍被认证/授权/分区隔离拦截。
3. **到期副本重现通道排查（严重/高）**：列表、搜索、详情、预览、下载、导出、API、缓存/全文索引全部过一遍。
4. **挂接快照与清单对平（高）**：实际挂接身份确为 `child-2`，核对 `parent=backup-1` 血缘、
   `contains` 身份、`partitions` 分区、`derived` 派生索引；多出/缺失/不可读范围登记为缺口。
5. **重建索引并确认清除（高）**：重建索引/缩略图/全文/缓存后，按 item 标识、文件名、内容指纹复查无命中。
6. **保全记录在位与策略重挂（高）**：`lease-7` 可读完整，hold 策略随恢复生效，清理作业跳过该历史凭证。
7. **同分区/同盘附件清点（中）**：逐个匹配台账，禁止因一个保全记录搭车跳过其他附件。
8. **关闭待查范围（中）**：`pending`/未列出项全部转 `checked` 且无矛盾，或补登合法保全后，审批才可继续。
9. **完整性材料与删除拦截（中/高）**：现有合成资料无哈希/签名，保留 `no_integrity_material`
   采集缺口；恢复后应比对备份校验值。任何删除前先过保全拦截。

## 5. 采集缺口与待查范围

- 缺口 `no_integrity_material`：三份 JSON 不含哈希/签名，且工具按设计不接触真实资料，
  因此无法核对实际字节完整性——该缺口保留，需由备份校验值与恢复后比对补齐。
- 待查范围：`restored-2 / index-a`（独立验证回执标记 `pending`）。
- 若出现引用不存在的快照/身份、台账缺分类、同名文件不同归属、台账更正冲突等，
  工具同样不会“往干净里判”，而是写入 `gaps` 与 `pending_scope`。

## 6. 可反复使用

```sh
python3 audit.py --format text                 # 中文文本报告
python3 audit.py                               # 完整 JSON（CI/二次处理）
python3 audit.py --records /path/to/dir --as-of 20
python3 audit.py --check                       # 审批门禁：未全部通过 -> 退出码 3
python3 records_view.py audit --format text    # 也可从原读取入口进入
python3 -m unittest -v                         # 读取测试 + 审计规则测试（共 38 个）
```

替换 `--records` 目录即可审计后续批次的合成清单与回执；三份来源仍为
`retention.json`、`snapshots.json`、`restores.json`。
