# 本地文件完整性监控离线模拟器

纯 Python 3.12 标准库实现的本地文件完整性监控（FIM）**离线模拟器**。全部输入均为
合成数据（合成文件快照、合成对象表、HMAC-SHA256 合成签名），不访问任何宿主文件，
不需要网络与第三方依赖，CPU 即可运行。状态持久化在 SQLite，支持多进程并发采集、
真实杀进程后的崩溃恢复，并附带一个独立只读参考模型交叉校验。

## 运行

```bash
# 重放合成案例（退出码 0 = 引擎与参考模型一致）
python -m solution --input cases.json --output result.json

# 自动化测试（31 个用例）
python -m unittest discover -s tests -v
```

环境：Windows 原生 Python 3.12（开发实测 3.12.8 / SQLite 3.45.3），仅标准库。

## 目录结构

```
solution/
  __main__.py   CLI：python -m solution --input cases.json --output result.json
  paths.py      受保护路径规范化（Windows 大小写折叠、分隔符归一）
  model.py      规范 JSON、SHA-256、基线 CAS、HMAC 签名、确定性 ID/回执
  errors.py     稳定错误码
  store.py      SQLite 模式与事务（BEGIN IMMEDIATE + busy_timeout，WAL）
  engine.py     采集入段、预检、三段式提交、崩溃恢复、数据缺口关闭
  reference.py  独立只读参考模型（纯内存复算，不碰 SQLite）
  runner.py     cases.json 重放器：引擎执行 + 参考模型比对
  workers.py    多进程/崩溃测试的独立进程入口
cases.json      可重放主案例（47 个操作）
tests/          unittest 套件（引擎语义 / 多进程 / 崩溃恢复 / 参考模型）
result.json     重放输出（由 CLI 生成）
```

## 监控规则

### 设备清单与对象表

- 每台设备的监控清单固定：**设备代数（generation）**、**基线版本（version）**、
  **受保护路径集合**、每个路径的**对象标识 oid 与 SHA-256**。
- 合成对象表 `oid -> {sha256, size}` 全局注册；未注册对象在入段时即被拒绝
  （`ERR_UNKNOWN_OBJECT`）。
- **硬链接别名**由对象表自然表达：多个受保护路径可引用同一 oid
  （如 `C:/App/a.exe` 与 `C:/App/b.exe` 都指向 `O1`）。
- 路径按 Windows 语义规范化：`\`/`/` 等价、`.` 段与重复分隔符折叠、
  **大小写折叠**（盘符大写、其余小写）。`C:\App\A.EXE` 与 `c:/app/a.exe` 是同一路径。
- 基线内容寻址：`CAS = SHA-256(canonical({device, version, entries}))`，
  基线不可变，设备当前视图 = 当前基线 CAS 指向的清单。

### 批次、范围与分段观测

- 变更输入按**批次（batch）**组织，批次声明段数；每段绑定
  **设备代数 + 基线 CAS + 批次号 + 段序号**，可**乱序、并发**上报（多进程安全，
  写事务用 `BEGIN IMMEDIATE` 串行化）。
- 同一段重复上报且载荷一致 → 幂等接受（`duplicate: true`）；载荷冲突 →
  `ERR_DUPLICATE_SEGMENT`。
- 批次**完整** = 全部段到齐且各段范围之并恰好覆盖受保护路径一次（无重叠、无越界）。
- **缺段不会误报“全部文件消失”**：段不齐时预检直接拒绝
  （`ERR_INCOMPLETE_OBSERVATION`），不产生任何按文件的删除告警；批次可被
  `close_batch` 关闭，仅记一条 `data_gap` 告警（列出缺失段）；**晚到的段**被拒绝
  （`ERR_BATCH_CLOSED`）。
- 每个完整批次的提交**要么整体更新设备视图，要么保留原版**（单事务内翻转视图，
  崩溃由恢复逻辑补完或回滚，见下）。

### 预检与提交

- 观测完整后先产生**预检（precheck）**：一份落库的、不可执行的差异计划
  （`state='staged'`），自身不改变任何可信状态。
- **提交（commit）** 时重新核对：
  1. 设备代数未变（否则 `ERR_GENERATION_CHANGED`，如采集期间设备被重建）；
  2. 当前基线 CAS 与预检一致（否则 `ERR_BASELINE_SWAPPED`，如另一进程已替换基线）；
  3. 段集合仍完整（否则 `ERR_INCOMPLETE_OBSERVATION`）；
  4. 发布类预检的**签发权当前仍有效**（否则 `ERR_SIGNER_REVOKED`）且签名正确
     （否则 `ERR_BAD_SIGNATURE`）。
- 提交在 SQLite 中分三个阶段落库：**告警写入 → 视图原子翻转 → 幂等回执**。
  两个真实杀进程点（`os._exit`）位于阶段之间；重启时 `_recover()` 自动补完或中止，
  保证**每个提交恰好一份随版本固定的告警集合**（`(commit_id, path, kind)` 主键 +
  版本列）与**恰好一份回执**（`receipts.commit_id` 主键，重放幂等）。
- 回执内容确定：`commit_id / device / batch / kind / generation / base_cas /
  new_cas / version / alert_count / alerts_digest / receipt_digest`，
  同一预检重复提交返回同一回执（`cached: true`）。

### 告警分类（明确四分）

| 类别 | 含义 |
|---|---|
| `legit_release` | 合法发布：授权签名 + 已确认观测范围共同确认的基线变更（added/removed/changed） |
| `content_change` | 路径绑定了**从未被授权**的对象，或文件被删除（观测为 null） |
| `alias_change` | 路径改指**当前可信对象集内**的另一对象（硬链接/重命名级别的绑定变化） |
| `data_gap` | 观测数据缺口（缺段），按批次记录一次，绝不展开成“文件消失” |

### 信任规则（防洗白）

- 信任是**对象级**的，且只能由**已授权并提交成功的发布**授予；证明性观测
  （attestation）永不改变可信集。
- **过去未获授权的内容**（如只出现在被拒绝/证明性观测中的 `OX`）**不会**因为
  路径后来改名、或基线回退到旧版本而变为可信——测试
  `test_trust_not_laundered_by_rename_or_rollback` 逐步断言。
- 发布可以撤销已批准内容：对象从新基线移除后即不再可信，再次观测到它会产生
  `content_change`（参考模型用例 `ref-revoked-content`）。

## 输入格式（cases.json）

```json
{"case_id": "...", "ops": [ {"op": "..."}, ... ]}
```

操作一览（`submit_segment` 的 `generation`/`baseline_cas` 可写 `"current"`
由重放器按提交时设备状态解析，也可显式固定以模拟过期段）：

| op | 关键字段 | 说明 |
|---|---|---|
| `register_objects` | `objects: {oid: content}` | 注册合成对象（SHA-256 由内容推导） |
| `register_key` / `revoke_key` | `key_id`, `secret` | 登记/撤销签发密钥 |
| `create_device` | `device`, `baseline{version, entries, sign_with}` | 代数 1 创建设备（需授权签名） |
| `rebuild` | `device`, `baseline` | 设备重建：代数 +1 并切换到新基线 |
| `submit_segment` | `device,batch,segment_count,index,observations{path: oid|null}` | 上报一段观测（null = 文件缺失） |
| `precheck` | `device,batch[,release{...}][,as:name]` | 生成预检；`as` 命名便于后续引用 |
| `commit` | `precheck: "last"|name|id` | 提交预检，产出回执 |
| `close_batch` | `device,batch` | 关闭缺段批次，记 `data_gap` |
| `receipt` | `commit: "last"|id` | 幂等读取回执 |
| `view` | `device` | 读取当前可信视图 |

发布规格 `release` 与 `baseline` 同形：`{version, entries:[[path,oid]...],
sign_with: key}` 或显式 `{key_id, signature}`（用于伪造签名用例）。

## 输出格式（result.json）

```json
{
  "case_id": "fim-sim-main",
  "ops": [
    {"index": 0, "op": "register_objects", "status": "ok", "result": {...}},
    {"index": 14, "op": "precheck", "status": "error",
     "code": "ERR_INCOMPLETE_OBSERVATION", "detail": "missing segments: [1]"}
  ],
  "final_views": {"dev-1": {"generation": 2, "version": 10,
                            "baseline_cas": "...", "entries": [...],
                            "trusted_objects": ["O1", "O2"]}},
  "reference": {"match": true, "mismatches": []}
}
```

告警记录：`{kind, path, base_oid, new_oid, detail}`（回执中按 `version` 固定并摘要）。

## 错误码

| 错误码 | 触发条件 |
|---|---|
| `ERR_DEVICE_EXISTS` / `ERR_DEVICE_NOT_FOUND` | 设备重复创建 / 不存在 |
| `ERR_KEY_NOT_FOUND` | 引用了未登记的密钥 |
| `ERR_SIGNER_REVOKED` | 提交时签发权已被撤销 |
| `ERR_BAD_SIGNATURE` | 基线签名与 CAS 不匹配 |
| `ERR_UNKNOWN_OBJECT` / `ERR_OBJECT_CONFLICT` | 对象未注册 / 同 oid 不同哈希 |
| `ERR_DUPLICATE_PATH` | 清单或段内路径规范化后重复 |
| `ERR_BATCH_NOT_FOUND` / `ERR_BATCH_CLOSED` / `ERR_BATCH_COMPLETE` | 批次不存在 / 已关闭（含晚到段）/ 已完整不可关闭 |
| `ERR_DUPLICATE_SEGMENT` | 同段序号载荷冲突 |
| `ERR_SCOPE_MISMATCH` | 段头与批次不一致、范围越界/重叠/未覆盖受保护路径 |
| `ERR_INCOMPLETE_OBSERVATION` | 缺段时预检/提交 |
| `ERR_OBSERVATION_MISMATCH` | 观测未确认发布内容 |
| `ERR_BASELINE_NOT_FOUND` | 段/预检钉住的基线 CAS 未知 |
| `ERR_GENERATION_CHANGED` | 预检后设备代数变化（设备重建） |
| `ERR_BASELINE_SWAPPED` | 预检后当前基线被替换 |
| `ERR_PRECHECK_NOT_FOUND` / `ERR_RECEIPT_NOT_FOUND` | 预检 / 回执不存在 |

CLI 退出码：`0` 重放成功且与参考模型一致；`2` 输入/执行故障；`3` 引擎与参考模型不一致。

## 测试覆盖

- `tests/test_engine.py`（18）：大小写折叠、内容变化/删除、别名变化、同名新对象、
  多别名一致性、幂等提交、缺段+晚到段、重复段、未知对象、范围越界、合法发布、
  观测不匹配、伪造签名、签发权撤销、改名/回退防洗白、基线替换与代数变化守卫。
- `tests/test_concurrency.py`（5，spawn 独立进程）：两进程并发乱序入段；
  采集期间另一进程重建设备 → `ERR_GENERATION_CHANGED`；预检后另一进程替换基线 →
  `ERR_BASELINE_SWAPPED`；缺段关闭后晚到段 → `ERR_BATCH_CLOSED`；另一进程撤销签发权 →
  `ERR_SIGNER_REVOKED`。
- `tests/test_crash_recovery.py`（2）：工作进程在“告警已写未翻转”（exit 42）与
  “已提交未回执”（exit 43）两处被真实杀死，重启恢复后断言每个提交恰好一份
  随版本固定的告警与一份回执，且重复提交幂等。
- `tests/test_reference.py`（6）：独立只读参考模型覆盖路径大小写折叠、同对象多别名、
  同名新对象、已批准内容撤销；并对 shipped `cases.json` 与 CLI 端到端结果做
  引擎 ↔ 参考模型全量比对。

## 实测结果（本机，Windows 11 / Python 3.12.8）

```
$ python -m solution --input cases.json --output result.json
case=fim-sim-main ops=47 domain_errors=6 reference_match=True   # 退出码 0

$ python -m unittest discover -s tests -v
Ran 31 tests in ~3.4s
OK
```

主案例重放要点（result.json 可复核）：

- 干净证明（含大小写混写路径、乱序两段）→ 0 告警，回执版本 1；
- 内容变化 + 删除 → 2 条 `content_change`；重复提交返回同一回执（`cached: true`）；
- 缺段批次 → `ERR_INCOMPLETE_OBSERVATION` → 关闭产生 1 条 `data_gap`，
  晚到段 → `ERR_BATCH_CLOSED`，全程无“文件消失”误报；
- 授权发布 v2（改 2、增 1、删 1）→ 4 条 `legit_release`，可信集变为 `{O2,O5,O6}`；
  旧内容 `O1` 再次观测 → `content_change`；
- 回退发布 v3 后，从未授权的 `OX` 依旧 `content_change`（防洗白）；
- 预检后基线被 v4 替换 → 旧预检提交 `ERR_BASELINE_SWAPPED`；
- 撤销 `k-rel` 后其发布提交 → `ERR_SIGNER_REVOKED`；伪造签名 → `ERR_BAD_SIGNATURE`；
- 设备重建（代数 2）后旧预检提交 → `ERR_GENERATION_CHANGED`；
- 最终视图：代数 2、基线版本 10、可信对象 `{O1, O2}`。
