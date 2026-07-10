# DeepAudit 改进文档

> 课程：2026 春《网络空间安全综合实验》选题一（基于大模型智能体的开源项目安全缺陷自动审计和验证系统）
> 基线项目：DeepAudit（开源，国内首个多智能体代码漏洞挖掘系统）
> 本文档目的：基于对 **20 款主流开源项目** 的实测（见 `一些项目的报告导出/`），梳理 DeepAudit 的可改进点，并给出**具体、可实现、可演示**的修改方案，作为课程作业的**自研差异化**依据。

---

## 0. 修改总览

| # | 改进项 | 类别 | 演示价值 | 工作量 | 关联缺陷 |
|---|---|---|---|---|---|
| 1 | 仓库 URL 深度解析（tag / commit / tree / blob） | 输入模块 | ⭐⭐⭐⭐⭐ 立刻可演示 | 小 | 运行文档 §4.1 |
| 2 | SCA 强制前置 + Recon 编排硬约束 | Agent 编排 | ⭐⭐⭐⭐⭐ 直接命中已知 CVE | 中 | 运行文档 §4.2 |
| 3 | C/C++ 语言动态验证工具链 | 沙箱工具 | ⭐⭐⭐⭐⭐ 唯一能真正复现 openvpn 类 C 项目漏洞 | 大 | C 项目动态验证缺失 |
| 4 | 低置信度发现的**验证回压** / 二次分析 | 验证智能体 | ⭐⭐⭐⭐ 直接降低误报 | 中 | 20/20 项目大量 60% 置信度未验证发现 |
| 5 | 证据链结构化 & 报告去空洞化 | 报告 | ⭐⭐⭐⭐ 满足选题"证据链"硬指标 | 中 | 报告样本中"src/xx.c:1690 - xxx"这种一句话发现 |
| 6 | 差量增量扫描 & 缓存 | 性能 | ⭐⭐⭐ 大项目重扫友好 | 中 | maccms 45min / openvpn 8.5min |
| 7 | 多 Agent 交叉复核（Analysis × Verification 投票） | 智能体架构 | ⭐⭐⭐⭐ 对标 AgentStalker 的裁决 | 中 | 单一 Verification 通过率极低 |
| 8 | 规则包 + LLM 混合的 SAST 前哨 | 扫描前置 | ⭐⭐⭐ 让 Analysis 有热点起步 | 小 | Analysis 从零翻源码浪费 token |

> 建议实现顺序：**1 → 2 → 3 → 4 → 5 → 7 → 8 → 6**，前 5 项完成就足够撑起 20 分钟答辩，7-8 是加分项，6 属于性能优化最后做。

---

## 1. 仓库 URL 深度解析（tag / commit / tree / blob）

### 1.1 当前问题（运行文档 §4.1）

- 用户传入 `https://github.com/pallets/flask/tree/2.0.0`，DeepAudit 忽略 `2.0.0`，仍拉 `main` 分支。
- 表现：报告里显示的行号、CVE 都对不上历史版本。
- 根源：`backend/app/utils/repo_utils.py:parse_repository_url()` 仅取 `path_parts[-2], path_parts[-1]` 作为 owner/repo，完全没解析 `/tree/…`、`/blob/…`、`/commit/…`、`/releases/tag/…` 等子路径。

### 1.2 修改方案

**目标**：URL 里明写了什么就扫什么，支持四种 ref 形态：`branch`、`tag`、`commit sha`、`release tag`。

**关键改动文件**：

- `backend/app/utils/repo_utils.py`
- `backend/app/api/v1/endpoints/projects.py`（`create_project` / `scan_project` 两处）
- `backend/app/services/scanner.py`（`get_github_files` 等）
- 前端 `frontend/src/pages/Projects/CreateProject.vue`（若走 URL 输入框）—— UI 增一个"检测到的 ref: `2.0.0`（tag）"提示。

**`parse_repository_url` 建议接口升级**：

```python
# 返回值新增字段
{
    "base_url": "...",
    "owner": "pallets",
    "repo": "flask",
    "server_url": "...",
    "ref": "2.0.0",          # 解析出来的 tag/branch/commit
    "ref_type": "tag",        # "tag" | "branch" | "commit" | None
    "path_in_repo": None,     # /blob/xxx/README.md 时才有值
    "project_path": "pallets/flask",
}
```

**解析规则**（GitHub / GitLab / Gitea 通用）：

| 路径片段 | 含义 | ref_type |
|---|---|---|
| `/tree/<ref>` | 分支或 tag，需要二次判定 | `tag` \| `branch` |
| `/blob/<ref>/<path>` | 分支或 tag + 具体文件 | 同上 |
| `/commit/<sha>`、`/-/commit/<sha>` | commit hash | `commit` |
| `/releases/tag/<tag>` | release tag | `tag` |
| `/-/tree/<ref>`（GitLab） | 同 `/tree/` | 同上 |

**ref_type 判定**：拿到 ref 后，用 GitHub API `/repos/{owner}/{repo}/git/ref/tags/{ref}`（或 `/branches/{ref}`）先查一遍；查不到再退化为按长度启发式：40 位 hex 视为 commit。

**下游改动**：

- `Project.default_branch` 之外新增 `pinned_ref`、`pinned_ref_type` 两个字段（数据库迁移一次），扫描时优先用 `pinned_ref`。
- `scanner.get_github_files(repo_url, branch, ...)` 改成接受 `ref`，直接用 `?ref={ref}` 参数请求 contents API，无需区分 tag/branch。
- `agent-tasks` 创建时把 `pinned_ref` 传给 Recon Agent 的 `project_info`，让 Agent 在生成报告时把版本号写进结论。

### 1.3 演示脚本

答辩演示时提前准备两个对比：

1. 老 DeepAudit + `https://github.com/pallets/flask/tree/2.0.0` → 扫到的是 main 分支代码。
2. 自研版 + 同 URL → 前端页面显示 `锚定版本: 2.0.0 (tag)`，报告里出现的行号能直接在 GitHub `flask@2.0.0` tag 页面点开对上。

### 1.4 验收指标

- 20 个测试项目里所有含 `/tree/`、`/blob/`、`/commit/` 的 URL 都能正确锁版本。
- 单元测试 `tests/utils/test_repo_utils.py` 覆盖至少 12 条 URL 样本。

---

## 2. SCA 强制前置 + Recon 编排硬约束

### 2.1 当前问题（运行文档 §4.2）

- OpenVPN 扫描：91 次工具调用，**全花在 `read_file` / `search_code`**，没跑 `osv_scan` / `semgrep_scan`。
- 后果：Recon 花大量 token 从零"手翻"依赖清单；一批已经公开的 CVE 完全没被 SCA 挖出来。
- 根源：Recon Agent 的 system prompt 里只是"推荐"用 `osv_scan`，是软约束；`osv_scanner` 工具存在（`external_tools.py:1045`）但 LLM 不主动调。

### 2.2 修改方案

**思路**：把 SCA 从 "LLM 决策" 改为 "确定性流水线的第一步"（这也是 AgentStalker 的做法：静态建模 → 攻击图 → 沙箱 → 裁决）。

**改动 A：新增 `PreflightStage`（在 Recon 之前跑）**

新增文件 `backend/app/services/agent/stages/preflight.py`：

```
职责：
1. 扫项目根目录 & 常见子目录，把所有清单文件（依赖 manifest）列出来
2. 对每个 manifest 强制跑一次 osv-scanner
3. 对 secrets 强制跑一次 gitleaks
4. 对全项目跑一次 semgrep --config auto
5. 把结果结构化写入 task.metadata['preflight'] 供后续 Agent 消费

manifest 匹配清单（不需要 LLM 判断）：
    requirements.txt | Pipfile.lock | poetry.lock | setup.py | setup.cfg | pyproject.toml
    package.json | package-lock.json | pnpm-lock.yaml | yarn.lock
    go.mod | go.sum
    pom.xml | build.gradle | build.gradle.kts
    Cargo.toml | Cargo.lock
    composer.json | composer.lock
    Gemfile | Gemfile.lock
    conanfile.txt | vcpkg.json     ← C/C++ 也覆盖
    CMakeLists.txt                 ← 只用来识别 C/C++ 项目
```

**改动 B：Recon prompt 收紧**

`recon.py` 的 `RECON_SYSTEM_PROMPT` 里加入：

```
## 前置结果（不允许忽略）
Preflight 阶段已经跑完 SCA/Secrets/Semgrep，结果放在 preflight_summary 变量里。
你的任务不是重新做 SCA，而是：
1. 阅读 preflight_summary 中的每一条 CVE
2. 用 read_file / search_code 定位 CVE 影响的具体调用点
3. 输出 initial_findings 时，**每个 CVE 至少产生一条对应的 finding**
```

**改动 C：Orchestrator 增加硬校验**

`orchestrator.py` 在把 Recon 结果交给 Analysis 之前，做一次断言：

```python
if preflight_summary["sca_findings"] and not any(
    f.get("source") == "sca" for f in recon_result["initial_findings"]
):
    # Recon 忽略了 SCA 结果，回退重跑一次，或者手动注入
    recon_result["initial_findings"].extend(
        _synthesize_sca_findings(preflight_summary["sca_findings"])
    )
```

### 2.3 复用现有工具

不要新写工具，直接调 `external_tools.py` 里已有的：

- `SemgrepScanTool`（189 行开始）
- `OsvScanTool`（1045 行开始）
- `GitleaksScanTool`

只是**把它们从"LLM 可选调用"提升为"流水线强制调用"**。

### 2.4 演示价值

- OpenVPN 项目：新增 SCA 后应能命中若干已知 CVE（例如 openvpn-2.5 系列的历史 CVE），弥补现在 12 个漏洞 0 验证的窘境。
- maccms10 项目：composer.json 的 SCA 立刻找出 ThinkPHP 已知 RCE。

### 2.5 验收指标

- 每个扫描任务 100% 触发 Preflight，任务的 `events` 表能看到 `stage=preflight` 事件。
- SCA 命中的 CVE 100% 出现在最终报告里，且带 `source: "sca"` 字段。

---

## 3. C/C++ 语言动态验证工具链（重点，唯一能真正给 openvpn 类项目跑 PoC）

### 3.1 当前问题

- `backend/app/services/agent/tools/sandbox_language.py` 已经支持 PHP / Python / JS / Java / Go / Ruby / Shell，**没有 C/C++**。
- OpenVPN 报告 12 个漏洞 0 验证，5 个 PoC 全部标注"无法构造有效的 PoC"（见 `一些项目的报告导出/项目1-OpenVPN的测试报告.md`）。
- 根源：Verification Agent 缺一个能"编译 + 运行 + 触发"C 代码的沙箱工具，只能空手写描述性 PoC。

### 3.2 修改方案

新增 `sandbox_language.py` 里 **`CTestTool` / `CppTestTool`** 两个类（参考 `JavaTestTool` 的结构，Java 已经做了"编译 + 运行"两段式，可以照搬）。

**沙箱镜像**：`deepaudit/sandbox` 镜像里加装 `gcc`, `g++`, `make`, `cmake`, `clang`, `valgrind`, `libasan`（AddressSanitizer 用于内存类漏洞证据）。

**关键设计点**：

1. **两种运行模式**：

   | 模式 | 场景 | 命令 |
   |---|---|---|
   | `snippet` | 单文件片段 PoC | `gcc -fsanitize=address -g /tmp/poc.c -o /tmp/poc && /tmp/poc <args>` |
   | `project` | 需要项目上下文（openvpn 就是这种） | `cd /workspace && ./configure && make && ./poc-driver` |

2. **`_build_wrapper_code`**：接收漏洞函数原型 + 触发参数，自动生成一个 `main()` 调用者。示例：

   ```c
   // wrapper generated by CTestTool
   #include "stdio.h"
   #include "stdlib.h"
   // vuln 函数原型由 LLM 从源码里提取传入
   extern int vuln(const char *user_input);

   int main(int argc, char **argv) {
       if (argc < 2) return 1;
       int r = vuln(argv[1]);
       printf("[RESULT] rc=%d\n", r);
       return 0;
   }
   ```

3. **`_analyze_output` 扩展**：C 语言的漏洞证据识别要比脚本语言复杂，除了通用指标外，追加：

   - `AddressSanitizer:` 前缀 → 内存越界/UAF
   - `SEGV` / `signal 11` → 段错误
   - `stack-buffer-overflow` / `heap-buffer-overflow` → 缓冲区溢出
   - `LeakSanitizer` → 内存泄漏
   - 检查 stderr 里 `command not found` → 判定是命令注入成功

4. **构建缓存**：C 项目 `configure && make` 动辄 5-10 分钟，第一次编译后把 build 目录挂载 volume，同一 task 内后续验证复用。

### 3.3 特殊子工具：`FuzzTestTool`

C 项目审计中，AFL++ / libFuzzer 的价值远超"跑一次 PoC"。新增 `fuzz_test` 工具：

```python
# 输入：目标函数 + harness 代码
# 沙箱内跑：clang -fsanitize=fuzzer,address harness.c -o fuzz && ./fuzz -max_total_time=60
# 输出：崩溃样本 base64 + ASAN 报告
```

对 openvpn 这种项目，30 秒-2 分钟的短 fuzz 就能出真实证据链。

### 3.4 Verification Agent 侧改动

`verification.py` 的 system prompt（`VERIFICATION_SYSTEM_PROMPT`）里增加：

```
## C/C++ 项目验证策略
- 简单函数：用 c_test 工具，传函数原型 + 触发参数
- 需要项目上下文：用 c_test project 模式，指定 configure/make 命令
- 内存类漏洞（UAF/buffer overflow）：优先跑 fuzz_test，AddressSanitizer 报告作为证据
- 不允许输出 "无法构造有效的 PoC"，只允许输出 "已尝试 X/Y/Z，均未触发" 并附命令日志
```

`UniversalCodeTestTool._testers` 字典里注册 `"c"`, `"cpp"`, `"c++"` 三个 key。

### 3.5 验收指标

- OpenVPN 项目重跑，至少 3 个漏洞产生真实的编译日志 + 运行输出（可以是"未触发"，但必须有真实日志，禁止空 PoC）。
- 沙箱镜像里 `gcc --version && clang --version && cmake --version` 全部可用。

### 3.6 涉及文件

- 新增：`backend/app/services/agent/tools/sandbox_c.py`
- 修改：`backend/app/services/agent/tools/sandbox_language.py`（把 `CTestTool` 挂进 `UniversalCodeTestTool`）
- 修改：`docker/sandbox/Dockerfile`（装编译器）
- 修改：`backend/app/services/agent/prompts/`（Verification 提示词）

---

## 4. 低置信度发现的验证回压 / 二次分析

**✅ 已实现 (2026-07-08)**

实现要点：
- 新增 `backend/app/services/agent/agents/refinement.py`（`RefinementAgent`）
- 分桶：conf≥0.8 直接放行；0.5≤conf<0.8 走 Refinement 精修；conf<0.5 直接丢
- 精修流程：确定性 `read_file(l±30)` + 可选 `search_code(sink)` → 单次 LLM 判决 → verdict ∈ {confirmed, false_positive, still_unclear}
- Orchestrator 硬约束：Analysis 完成后必须先 Refinement 再 Verification（`_dispatch_agent` 直接拦截）
- 新的 handoff 链路：Recon → Analysis → Refinement → Verification
- 报告端：`扫描但过滤` 分区（Refinement 丢弃）+ `待人工确认` 分区（still_unclear）
- 涉及文件：refinement.py（新）/ orchestrator.py / agents/__init__.py / api/v1/endpoints/agent_tasks.py

### 4.1 当前问题

抽 20 份报告归纳出的通病：

- 大量 `AI 置信度 60%` 的发现，描述是 "src/xx.c:1690 - argv_parse_cmd解析route_script并执行"，一句话，没有代码片段、没有数据流、没有证据。
- 这类 finding 全部 `[未验证]`，Verification Agent 直接跳过，最终落进报告制造噪声。
- 严重违反选题要求里的 "误报率高 / 缺乏证据链" 两条核心痛点。

### 4.2 修改方案

**策略**：不是简单丢弃低置信度发现，而是**触发一次针对性二次分析**（Analysis Agent 复审），再决定丢弃或升格。

**流程**：

```
Analysis 一次输出
      │
      ▼
  分类三桶
   ├─ confidence ≥ 0.8 → 直接进 Verification 队列
   ├─ 0.5 ≤ confidence < 0.8 → 进「Refinement」子阶段
   └─ confidence < 0.5 → 丢弃，但记录到 audit_trail 供报告"扫描但过滤掉"栏目使用
```

**Refinement 子阶段**（新加）：

对每个中置信度发现，让 Analysis Agent 再跑一轮，但这次给它更严格的输入：

```
"这个发现的原始描述是 X，file={f}, line={l}。请：
1. read_file 拉出 file 的 [l-30, l+30] 区间
2. 至少做一次 trace_data_flow（新工具，见 §8）或 search_code 找 sink 的所有 caller
3. 输出：
   {
     "verdict": "confirmed" | "false_positive" | "still_unclear",
     "code_snippet": "...",   // ≥ 10 行真实代码
     "data_flow": "user_input -> f() -> g() -> sink",
     "why": "...",
     "new_confidence": 0.xx
   }
"
```

Refinement 输出 `false_positive` 的直接丢；`confirmed` 的送 Verification；`still_unclear` 的进入报告的独立"待人工确认"分区。

### 4.3 涉及文件

- 新增：`backend/app/services/agent/agents/refinement.py`
- 修改：`orchestrator.py`（在 Analysis 之后插入 Refinement 阶段）
- 修改：`report_generator.py`（新增"扫描但过滤"和"待人工确认"两个分区）

### 4.4 验收指标

- 20 份报告重跑后，`confidence 60%` 的一句话 finding 数量下降 ≥ 70%。
- 报告里"高危漏洞"数量下降，但**每一条都带 ≥ 10 行代码片段 + 数据流**。

---

## 5. 证据链结构化 & 报告去空洞化

**✅ 已实现 (2026-07-08)**

实现要点：
- 新增 `backend/app/services/agent/evidence_chain.py` — `EvidenceChain` 数据类
- 五段结构：`source_locations` / `call_path` / `taint_flow` / `verification` / `references`
- 完整度打分 `n/5`，缺项显式打 `⚠️ 证据不完整 (缺少: xxx)`
- 存储方式：**不改 DB schema**，塞到现有 `AgentFinding.finding_metadata.evidence_chain` JSON 子键
- `_save_findings` 抽 EvidenceChain 时机在写库前，Markdown/JSON 报告端直接读
- Analysis 的 Final Answer schema 增加 `call_path` / `taint_flow` / `cwe_id`
- Verification 的 Final Answer schema 增加 `verification_result.command/output/exit_code`
- Refinement 的 verdict schema 也增加 `call_path` / `cwe_id`
- Verification prompt 硬禁止 "无需修复"/"提供了有效的保护"/"该代码是安全的" 类空洞措辞
- 报告 Markdown 每条 finding 新增"证据链"面板：5 小节 + 完整度徽章
- 报告"审计指标"新增"证据链完整度: 平均 X.X/5 (完整 N 条, 严重不足 M 条)"

### 5.1 当前问题

对照选题要求 "证据链需包含：文件位置 + 调用路径 + 验证结果"：

- 现有报告只满足 "文件位置"，"调用路径" 完全没有，"验证结果" 大多为空。
- 大量描述性文字如 "无需修复。argv_printf() 和 execve() 提供了有效的保护" —— 这不是证据，是 LLM 自我圆场。

### 5.2 修改方案

**统一证据链 Schema**（写进 `Finding` 数据模型）：

```python
class EvidenceChain(BaseModel):
    source_locations: List[SourceLocation]  # 文件+行号+函数名+代码片段
    call_path: List[CallEdge]               # [{"from": "handler.py:12:index", "to": "utils.py:34:sanitize"}]
    taint_flow: Optional[TaintFlow]         # 污点从哪进 / 经过哪些点 / 到哪个 sink
    verification: VerificationEvidence      # 验证方法 + 命令 + 输出 + 退出码 + 判定
    references: List[Reference]             # CVE / CWE / 相关 commit
```

**报告模板改造**：

`report_generator.py` 里每个 finding 强制展开如下小节，任何一节缺失都要打 `⚠️ 证据不完整` 标记：

```markdown
### [SEV] Title

**证据链完整度**：4/5 ✔️ (缺少：taint_flow)

**1) 源位置**
- file.c:123 (函数 `foo`)
   ```c
   line 120 ...
   ...
```

**2) 调用路径**
`main → parse_arg → foo → system`（3 跳）

**3) 污点流**
`argv[1] → parse_arg::buf → foo::user_input → system::cmd`

**4) 验证**
- 方法：c_test (project 模式, AddressSanitizer)
- 命令：`gcc -fsanitize=address ...`
- 输出：`==12== ERROR: AddressSanitizer: heap-buffer-overflow ...`
- 判定：**已验证**（触发 ASAN）

**5) 参考**
- CWE-78: OS Command Injection
- CVE-XXXX-XXXX（若匹配）
### 5.3 涉及文件

- 修改：`backend/app/models/finding.py`（数据库迁移，追加 evidence_chain JSON 字段）
- 修改：`backend/app/services/report_generator.py`
- 修改：`analysis.py` / `verification.py` 的输出 schema，强制填充这些字段

### 5.4 验收指标

- 报告里所有 finding 至少填齐"源位置 + 调用路径 + 验证结果" 3/5 项，缺项显式标注。
- 禁用"无需修复"、"提供了有效的保护"这类无证据结论，Verification prompt 里明文禁止。

---

## 6. 差量增量扫描 & 缓存

### 6.1 当前问题

- maccms10 一次 45 分钟，重跑一次浪费；openvpn 一次 8.5 分钟，SCA 结果、Recon 结果都可以复用。
- Token 消耗：单项目动辄 150 万 tokens，成本感人（课程有 300 元补助上限）。

### 6.2 修改方案

**三级缓存**（key = `sha256(project_files_tree)`）：

1. **Preflight 缓存**：同一 commit 的 SCA/Semgrep 结果直接读 Redis。
2. **File-level embedding 缓存**：`rag` 服务里已有部分实现，扩展成基于文件 hash 的持久化缓存。
3. **Finding 缓存**：一个 finding 的 `(file_path, line, rule_id)` 三元组作为 key，重跑同一 commit 时直接把已验证结果搬过来。

**增量扫描 API**：

新增 `POST /api/v1/projects/{id}/scan/incremental?since=<commit_sha>`，只扫 diff 涉及的文件，节约大项目重跑成本。

### 6.3 验收指标

- OpenVPN 第二次同 commit 扫描耗时下降 ≥ 60%。
- 加一行代码后的增量扫描只跑改动文件 + 其反向依赖。

---

## 7. Analysis × Verification 交叉复核（多智能体投票）

### 7.1 当前问题

- 单一 Verification Agent 一票通过/否决，本质上是"另一个 LLM 说是就是"，仍然是幻觉链条。
- 选题里 5 个对标项目中，AgentStalker、ESAA-Security 明确提到"证据裁决"、"事件溯源确定性流水线"。

### 7.2 修改方案

**双盲验证**（对标"证据裁决"）：

对每个"高危 + 已生成 PoC"的 finding，启动 **两个独立 Verification Agent 实例**：

- Agent A：走沙箱动态验证路径（`sandbox_exec` / `c_test` 等）
- Agent B：走静态复核路径（重新读代码 + `trace_data_flow` + `search_code`）

**裁决规则**：

| A 结论 | B 结论 | 最终                                        |
| ------ | ------ | ------------------------------------------- |
| 已验证 | 已验证 | **VERIFIED_HIGH_CONFIDENCE**                |
| 已验证 | 否决   | **CONFLICT** → 送第三方（Orchestrator）裁决 |
| 否决   | 已验证 | **CONFLICT** → 同上                         |
| 否决   | 否决   | **FALSE_POSITIVE**，丢弃                    |

**Orchestrator 裁决**：不是让 LLM 再猜一次，而是**要求 A、B 各出一段可执行证据**（命令 + 输出 or 数据流路径），Orchestrator 只做规则式合成，判定"证据强度"。

### 7.3 涉及文件

- 修改：`agents/verification.py` → 抽出 `VerificationAgentA`, `VerificationAgentB` 两个子类
- 修改：`agents/orchestrator.py` → 新增 `arbitrate()` 方法
- 新增 `models/finding.py` 的 `verdict` 字段：`unverified | verified | conflict | false_positive`

### 7.4 改动清单

####   1、文件: models/agent_task.py

  改动: AgentFinding 加 verdict (String) + cross_review (JSON) + to_dict() 补输出

####2、文件: alembic/versions/009_add_cross_review.py

  改动: 新迁移，加 verdict/cross_review 列 + verdict 索引（已 upgrade）

####3、文件: agents/verification.py

  改动: VerificationAgent.__init__ 新增 mode 参数（unified / dynamic / static）；差异化 addendum 加尾 + 工具白名单过滤

####4、文件: agents/orchestrator.py

  改动: ① 加 Tuple import<br>② dispatch 判断进入 _run_cross_review<br>③ 新增 5 个方法：_select_cross_review_targets /
  _run_cross_review / _run_single_verifier / _arbitrate / _normalize_verifier_output / _merge_verdict_into_all_findings

####5、文件: api/v1/endpoints/agent_tasks.py

  改动: ① 创建 verification_agent_a (dynamic) / _b (static)<br>② sub_agents 注册 verification_a / verification_b（LLM
  侧仍只见 verification，透明 fan-out）<br>③ _save_findings 消费 verdict 决定 status<br>④ AgentFindingResponse 加
  verdict / cross_review 字段<br>⑤ AgentFinding() 构造器写入 verdict/cross_review

---

## 8. 规则包 + LLM 混合 SAST 前哨

### 8.1 当前问题

- Analysis Agent 冷启动阶段全靠 `list_files` / `read_file` 逐个翻源码，token 消耗大且遗漏率高。
- 现有 `smart_scan_tool.py`, `pattern_tool.py` 已经有规则匹配基础，但被 Analysis Agent 忽略。

### 8.2 修改方案

**Preflight 补一步 SAST**：

- 对 PHP → `phpstan --level=max` + `psalm`
- 对 Python → `bandit -r . -f json`
- 对 JS/TS → `eslint --plugin security` + `njsscan`
- 对 C/C++ → `cppcheck --enable=all --xml` + `flawfinder`
- 对 Java → `spotbugs --xml`
- 通用 → `semgrep --config auto`（已存在）

结果结构化后作为 Analysis Agent 的**热点候选清单**：

Analysis 的第一步不再是"我看看这个项目有什么" ，而是：
"这里有 47 个候选热点（附文件行号 + 规则名），逐个判断真实性"

### 8.3 新工具：`trace_data_flow`

对多语言实现一个轻量 taint analysis 工具（Python 用 `libcst`、C 用 `pycparser` 或 `tree-sitter`），给 Refinement 阶段用于生成 §5 里要求的 `taint_flow` 字段。

**不追求完美**，只需覆盖典型 sink：
- SQL 拼接（`.execute(f"SELECT ...{x}")`）
- 命令执行（`os.system`, `subprocess`, `Runtime.exec`, `system()`）
- 文件路径（`open`, `fopen`, `readFile`）
- eval / exec

---

## 附录 A：改动清单速查

| 模块       | 新增                                                         | 修改                                                         |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 数据模型   | `EvidenceChain` schema                                       | `Project.pinned_ref`、`Finding.evidence_chain`、`Finding.verdict` |
| 输入解析   | `tests/utils/test_repo_utils.py`                             | `utils/repo_utils.py`、`services/scanner.py`                 |
| 编排流水线 | `services/agent/stages/preflight.py`、`agents/refinement.py` | `agents/orchestrator.py`、`agents/recon.py`、`agents/analysis.py`、`agents/verification.py` |
| 沙箱工具   | `tools/sandbox_c.py`、`tools/fuzz_tool.py`、`tools/trace_data_flow.py` | `tools/sandbox_language.py`（挂 C/C++）、`docker/sandbox/Dockerfile` |
| 报告       | 无                                                           | `services/report_generator.py`                               |
| 前端       | 版本锚定展示、证据链可视化                                   | 项目详情页、报告页                                           |

---

## 附录 B：对课程作业 20 个项目的分工影响

现有 20 份报告里能"重跑并有明显改进"的候选：

| 项目                       | 主要改进关注点                  | 用来演示的功能     |
| -------------------------- | ------------------------------- | ------------------ |
| 项目1 OpenVPN              | §3 C 语言验证 + §2 SCA          | C 项目动态验证首秀 |
| 项目2 maccms10             | §2 SCA (composer) + §4 二次分析 | 已知 CVE 链        |
| 项目3 Vulnerable-Flask-App | §1 URL 锚定 + §7 双盲           | 靶场证据链完整闭环 |
| 项目7 Flask 2.0.0          | §1 URL 锚定（tag=2.0.0）        | 老版本 CVE 命中    |
| 项目10 Gin 1.6.0           | §1 URL 锚定 + §2 SCA(go.sum)    | Go SCA             |
| 项目17 log4j 2.14.1        | §2 SCA + §7 双盲                | log4shell 直接命中 |
| 项目19 fastjson 1.2.24     | §2 SCA + §5 证据链              | RCE 证据完整       |

> 现场演示 3-5 个最能出成绩的即可。

---

## 附录 C：与选题要求的对齐检查

| 选题要求                                     | 修改项覆盖                            |
| -------------------------------------------- | ------------------------------------- |
| 支持 GitHub/GitLab URL / 本地目录            | §1（URL 强化，本地目录已支持）        |
| 自动语言识别、依赖与文件结构提取             | §2 Preflight                          |
| ≥ 2 类协作智能体，MCP/Skills/工具调用        | §7 双盲 + Refinement，总计 5 类 Agent |
| SQL 注入、命令注入、路径遍历、硬编码密钥     | 现有覆盖 + §3 C 项目补齐              |
| 验证智能体去误报                             | §4 + §7                               |
| 自动化漏洞利用 / PoC                         | §3 + §5                               |
| 证据链输出（文件位置 + 调用路径 + 验证结果） | §5（Schema 化）                       |
| 结构化审计报告                               | §5 报告改造                           |
| 与开源项目对比、突出创新点                   | 本文本身就是对比基线                  |
| ≥ 20 项目实测（含 openvpn / maccms v10）     | 已完成（`一些项目的报告导出/`）       |

---

## 附录 D：优先级 & 时间盘点

按 7/17 答辩倒推，建议以下节奏：

| 时间段               | 里程碑                                                    |
| -------------------- | --------------------------------------------------------- |
| Week 1 (7/8 – 7/10)  | 完成 §1（URL 锚定）+ §2（SCA 前置），跑通至少 5 个项目    |
| Week 1 (7/11 – 7/12) | 完成 §3（C 沙箱镜像 + CTestTool），OpenVPN 首次出真实 PoC |
| Week 2 (7/13 – 7/14) | 完成 §4 + §5，20 项目全部重跑一遍                         |
| Week 2 (7/15 – 7/16) | §7 双盲、报告 & PPT 定稿                                  |
| 7/17 上午            | 现场演示                                                  |

§6、§8 时间富裕就做，紧张就跳过，不影响验收硬指标。
