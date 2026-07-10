# DeepAudit 文件架构

> 面向课程作业阅读者：读完本文你应当能一眼看出 DeepAudit 的**每个目录 / 每个关键文件**分别在做什么，以及要在哪里改动才能实现`deepaudit修改文档.md`里的 8 项改进。
> 版本对应：`D:\网络空间安全综合实验\DeepAudit\`（当前工作副本）。

---

## 0. 顶层目录鸟瞰

```
DeepAudit/
├─ backend/               ← Python + FastAPI 后端（核心，Agent 全在这）
├─ frontend/              ← React + Vite + TypeScript 前端
├─ docker/                ← 沙箱镜像 Dockerfile & seccomp 策略
├─ docs/                  ← 官方文档（架构、部署、FAQ、CVE 复现示例）
├─ rules/                 ← 预置规则包（YAML 形式）
├─ scripts/               ← 一次性安装 / 环境检查脚本
├─ supabase/              ← Supabase 迁移（可选后端，实际未启用）
├─ 项目文档/              ← 本次课程作业自建文档目录
├─ docker-compose.yml            ← 主编排（backend/frontend/db/redis/adminer/sandbox）
├─ docker-compose.override.yml   ← 本地开发覆盖层（挂源码、暴露端口）
├─ docker-compose.prod.yml       ← 生产编排
├─ docker-compose.prod.cn.yml    ← 生产 + 国内镜像加速
├─ sgconfig.yml           ← Semgrep 全局配置（供沙箱 semgrep_scan 工具使用）
├─ tools.txt              ← 外部安全工具清单
├─ CVEList.md             ← 项目 README 里挂的历史 CVE 复现列表
├─ README.md / README_EN.md
├─ CHANGELOG.md / CONTRIBUTING.md / DISCLAIMER.md / LICENSE / SECURITY.md
```

理解 DeepAudit 只需要看两个方向：**backend/**（真正的智能体系统）+ **frontend/**（可视化 & 交互）；其它目录都是围绕这两者的运维/文档辅助。

---

## 1. `backend/` —— 后端与智能体系统

### 1.1 顶层文件

| 文件 | 作用 |
|---|---|
| `main.py` | FastAPI 应用入口，注册路由、CORS、生命周期钩子 |
| `Dockerfile` | 后端镜像构建 |
| `docker-entrypoint.sh` | 启动脚本：跑 alembic upgrade → 启 uvicorn |
| `start.sh` | 本地手动启动的便捷脚本 |
| `env.example` | 环境变量模板（`.env` 从这复制） |
| `pyproject.toml` / `requirements.txt` / `requirements-lock.txt` / `uv.lock` | 依赖清单，`uv` 是推荐的解析器 |
| `alembic.ini` | 数据库迁移配置 |
| `check_docker_direct.py` / `check_sandbox.py` / `verify_llm.py` | 部署自检脚本，运行前跑一次可以排查沙箱、LLM 连通性问题 |

### 1.2 `backend/alembic/` —— 数据库迁移

| 路径 | 作用 |
|---|---|
| `env.py` | Alembic 运行环境 |
| `script.py.mako` | 迁移文件模板 |
| `versions/` | 每一次表结构变更都是这里的一个 Python 文件（追加 `pinned_ref` 等新字段就要在这里加迁移） |

### 1.3 `backend/app/` —— 应用主体

#### 1.3.1 `backend/app/api/` —— HTTP 接口层

```
api/
├─ deps.py                       ← FastAPI 依赖注入（当前用户、DB 会话）
└─ v1/
   ├─ api.py                    ← 路由聚合，把 endpoints/ 下每一个模块挂到 /api/v1
   └─ endpoints/                ← 每一类资源一个文件
```

| endpoints 文件 | 对应的功能 |
|---|---|
| `auth.py` | 登录 / 注册（JWT） |
| `users.py` | 用户 CRUD |
| `config.py` | 当前用户的 LLM/其它配置读写、测试连通性 |
| `embedding_config.py` | Embedding 模型独立配置（RAG 用） |
| `projects.py` | 项目 CRUD、文件树、分支列表、发起普通扫描（**修改项 1 URL 深度解析主要改这里**） |
| `members.py` | 项目成员管理 |
| `scan.py` | 普通模式扫描、即时分析、上传 ZIP |
| `agent_tasks.py` | **Agent 深度审计**入口，创建任务、SSE 流、findings、报告导出 |
| `tasks.py` | 通用任务查询 |
| `rules.py` | 审计规则 CRUD |
| `prompts.py` | 提示词模板 CRUD |
| `ssh_keys.py` | SSH 密钥管理（拉取私仓） |
| `database.py` | 数据备份 / 恢复 / 清空 |

#### 1.3.2 `backend/app/core/` —— 全局基础设施

| 文件 | 作用 |
|---|---|
| `config.py` | Pydantic Settings，读 `.env`，暴露 `settings` 单例 |
| `security.py` | JWT 编解码、密码 hash |
| `encryption.py` | 加解密敏感字段（如存到 DB 的 SSH 私钥） |

#### 1.3.3 `backend/app/db/` —— 数据库层

| 文件 | 作用 |
|---|---|
| `base.py` | SQLAlchemy 声明式 Base |
| `session.py` | 异步引擎 & `AsyncSession` 会话工厂 |
| `init_db.py` | 首次启动时的种子数据（demo 用户等） |

#### 1.3.4 `backend/app/models/` —— ORM 模型（数据库表）

| 文件 | 表 | 说明 |
|---|---|---|
| `user.py` | `users` | 用户 |
| `user_config.py` | `user_configs` | 每用户的 LLM/嵌入/其它配置（LLM 配置真正落地的地方） |
| `project.py` | `projects` / `project_members` | 项目主表，含 `repository_url`、`default_branch`（**修改项 1 要加 `pinned_ref` / `pinned_ref_type`**） |
| `audit.py` | `audit_tasks` / `audit_issues` | 普通扫描任务和结果 |
| `agent_task.py` | `agent_tasks` / `agent_findings` / `agent_events` / `agent_checkpoints` 等 | Agent 深度审计相关的所有表；含状态机（PENDING → INDEXING → ANALYZING → VERIFYING …）、finding、SSE 事件、断点续跑 |
| `analysis.py` | `instant_analyses` | 即时分析历史记录 |
| `audit_rule.py` | `audit_rules` | 规则包 |
| `prompt_template.py` | `prompt_templates` | 提示词模板 |

#### 1.3.5 `backend/app/schemas/` —— Pydantic 请求/响应体

`user.py` / `token.py` / `audit_rule.py` / `prompt_template.py` —— 每个都是对应 API 的入参出参 DTO。数据库模型不能直接暴露给 HTTP，全部经此层过一次。

#### 1.3.6 `backend/app/utils/` —— 通用工具

| 文件 | 作用 |
|---|---|
| `repo_utils.py` | **`parse_repository_url()`**：把 GitHub/GitLab/Gitea URL 拆成 owner/repo/base_url。当前**只解析 owner/repo，不认识 `/tree/<ref>`、`/blob/`、`/commit/`**——修改项 1 的主战场 |

#### 1.3.7 `backend/app/services/` —— 业务服务层（重点区）

顶层单文件服务：

| 文件 | 作用 |
|---|---|
| `scanner.py` | 普通模式扫描主循环：拉文件树 → 拉文件内容 → 逐个丢给 LLM → 落库。含 `get_github_files` / `get_gitlab_files` / `get_gitea_files` / `get_*_branches`。**修改项 1 的下游改动点**（`branch` 参数改为 `ref` 语义） |
| `git_ssh_service.py` | SSH 私仓拉取（`ssh://git@…`），需配套 SSH Key |
| `zip_storage.py` | ZIP 上传后落盘/解压/复用 |
| `init_templates.py` | 首次启动初始化预置提示词模板 & 审计规则 |
| `report_generator.py` | PDF / Markdown / JSON 报告生成（WeasyPrint） |

##### 1.3.7.1 `services/llm/` —— LLM 抽象层

```
llm/
├─ base_adapter.py       ← 适配器抽象基类
├─ factory.py            ← 按 provider 名字造出对应适配器
├─ service.py            ← 上层业务用的封装：analyze_code、analyze_code_with_rules、通用 chat
├─ types.py              ← 请求/响应/消息类型
├─ tokenizer.py          ← Token 计数（供 memory_compressor / cost 估算）
├─ memory_compressor.py  ← 对话历史过长时压缩摘要
├─ prompt_cache.py       ← Anthropic prompt caching / DeepSeek KV cache 支持
└─ adapters/
   ├─ litellm_adapter.py     ← 通用 OpenAI 兼容协议（DeepSeek/OpenAI/Anthropic 大多走这里）
   ├─ doubao_adapter.py      ← 字节豆包
   ├─ baidu_adapter.py       ← 百度文心
   └─ minimax_adapter.py     ← MiniMax
```

##### 1.3.7.2 `services/rag/` —— 检索增强（代码语义搜索）

| 文件 | 作用 |
|---|---|
| `splitter.py` | 基于 tree-sitter 的智能代码分块（比按行切精准） |
| `indexer.py` | 分块 → embedding → 写向量库 |
| `embeddings.py` | 多 Embedding provider 抽象（OpenAI/Ollama/Cohere/HF/Jina/Azure） |
| `retriever.py` | 语义 + 关键字混合检索 |

`rag_tool.py`（在 agent/tools/ 里）把 retriever 包成 Agent 可调工具。

##### 1.3.7.3 `services/agent/` —— **多智能体核心（最重要）**

```
agent/
├─ config.py                ← AgentConfig：LLM 超时/重试/文件大小/文件后缀白名单 等
├─ event_manager.py         ← Agent 事件建模、SSE 广播、持久化到 agent_events 表
├─ json_parser.py           ← 容错 JSON 解析（LLM 输出常带 markdown/多余字段）
├─ evidence_chain.py        ← §5 证据链结构化：5 字段（source_locations / call_path / taint_flow / verification / references）的提取、完整性评分、Markdown 渲染
├─ agents/                  ← 智能体本体（详见 §1.3.7.4）
├─ tools/                   ← Agent 可调工具箱（详见 §1.3.7.5）
├─ core/                    ← 生产级基础设施（详见 §1.3.7.6）
├─ knowledge/               ← 漏洞/框架安全知识库（详见 §1.3.7.7）
├─ prompts/system_prompts.py← 系统提示词集中管理
├─ streaming/               ← SSE 三件套：stream_handler / token_streamer / tool_stream
├─ stages/                  ← 确定性前哨阶段（不含 LLM），当前含 preflight.py（§2 SCA/Secrets/SAST 预扫描）
└─ telemetry/tracer.py      ← 全链路追踪 span 采集
```

##### 1.3.7.4 `agent/agents/` —— 五个智能体 + 一个编排器

| 文件 | Agent | 定位 |
|---|---|---|
| `base.py` | `BaseAgent` + `AgentConfig` + `TaskHandoff` | 所有 Agent 的抽象父类：ReAct 循环、事件发射、工具调度 |
| `orchestrator.py` | Orchestrator | 编排层：动态决定下一步该派谁；持有 sub-agent 树。内含 §4 硬约束（Refinement 必跑）、§7 交叉复核（LLM 可见 verification，内部 fan-out 到 A/B 双盲或 MEDIUM 单侧） |
| `recon.py` | Recon | 侦察层：读项目结构、识别技术栈、推荐外部工具。Preflight 阶段做完确定性扫描后，Recon 消费其摘要并转成 initial_findings |
| `analysis.py` | Analysis | 漏洞分析层：ReAct 找漏洞，产出 `findings[]`（含 severity/ confidence / call_path / taint_flow） |
| `refinement.py` | Refinement | **§4 新增**：低置信度二次分析。按 confidence 分桶（≥0.8 passthrough、0.5–0.8 精修、<0.5 丢弃），产出 refined finding 清单替换 `_all_findings` |
| `verification.py` | Verification | 验证层：起沙箱跑 PoC，判定 finding 真假。支持三种 mode：`unified`（默认全能）、`dynamic`（A 侧，仅沙箱）、`static`（B 侧，仅读代码） |

##### 1.3.7.5 `agent/tools/` —— 智能体工具箱（Agent 的"手"）

| 工具文件 | 工具名 | 说明 |
|---|---|---|
| `base.py` | `AgentTool` / `ToolResult` | 工具抽象基类 |
| `file_tool.py` | `read_file` / `list_files` / `search_code` | 文件系统访问 |
| `pattern_tool.py` | `pattern_scan` | 危险模式正则匹配（OWASP Top 10 2025） |
| `smart_scan_tool.py` | `smart_scan` | 批量扫描组合拳，减少 LLM 工具调用轮数 |
| `code_analysis_tool.py` | `code_analysis` | LLM 深度分析单文件 |
| `rag_tool.py` | `rag_query` | 语义搜索代码（走 RAG 检索器） |
| `external_tools.py` | `semgrep_scan` / `gitleaks_scan` / `bandit_scan` / `npm_audit` / `osv_scan` / `safety_scan` … | **外部 SAST/SCA 工具封装**（Semgrep、Gitleaks、Bandit、npm audit、osv-scanner…）—— 修改项 2 的核心：这些工具已存在，但 Recon Agent 没被强制调 |
| `kunlun_tool.py` | `kunlun_scan` | 昆仑镜（Kunlun-M）静态审计集成，主打 PHP/JS |
| `sandbox_tool.py` | `sandbox_exec` / `sandbox_http` | 起 Docker 沙箱执行任意命令 / 发 HTTP 请求 |
| `sandbox_vuln.py` | 各类漏洞验证子工具 | 针对 SQLi / XSS / SSRF 等场景的专用验证 |
| `sandbox_language.py` | `php_test` / `python_test` / `javascript_test` / `java_test` / `go_test` / `ruby_test` / `shell_test` / `code_test`（通用调度） | 多语言沙箱执行器（**当前无 C/C++**，修改项 3 要在这加 `CTestTool` / `CppTestTool` / `FuzzTestTool`） |
| `run_code.py` | `run_code` | 通用代码执行（LLM 决定语言 + payload） |
| `thinking_tool.py` | `think` | LLM 自省推理工具（写 reasoning，不调用外部） |
| `reporting_tool.py` | `report_vulnerability` | **唯一合法上报 finding 的路径**，保证 finding 结构完整 |
| `agent_tools.py` | `create_sub_agent` / `send_message` 等 | 动态派生 sub-agent 用 |
| `finish_tool.py` | `finish_audit` | 主 Agent 结束审计任务的信号 |

##### 1.3.7.6 `agent/core/` —— 生产级基础设施

| 文件 | 作用 |
|---|---|
| `state.py` | 全局 Agent 状态（当前阶段、迭代次数、token 消耗、findings 累积） |
| `registry.py` | Agent 注册表 + 动态 Agent 树 |
| `graph_controller.py` | Agent 依赖图管理（谁调用谁） |
| `executor.py` | Agent 树实际执行器（含并行执行） |
| `context.py` | 分布式 trace / correlation id |
| `message.py` | Agent 间消息队列 |
| `persistence.py` | Agent 状态序列化到 `agent_checkpoints`，支持断点续跑 |
| `retry.py` / `circuit_breaker.py` / `rate_limiter.py` / `fallback.py` | 稳定性四件套：LLM 抖动时的重试 / 熔断 / 限流 / 降级 |
| `errors.py` | 结构化错误层次 + 恢复策略元信息 |
| `logging.py` | 结构化日志（自动注入 trace_id 等上下文） |
| `validation.py` | Agent 参数/输出校验 |

##### 1.3.7.7 `agent/knowledge/` —— 内置安全知识

```
knowledge/
├─ base.py              ← 知识模块抽象
├─ loader.py            ← 加载器（按需注入到 Agent context）
├─ rag_knowledge.py     ← RAG 版本的知识检索
├─ tools.py             ← 让 Agent 运行时可调 `query_knowledge` 之类的工具
├─ vulnerabilities/     ← 按漏洞类型划分的知识：auth / injection / xss / xxe / ssrf /
│                          csrf / crypto / path_traversal / open_redirect /
│                          deserialization / race_condition / business_logic
└─ frameworks/          ← 按框架划分：django / flask / fastapi / express / react / supabase
```

作用是给 Analysis / Verification 提供背景知识，避免 LLM 从零回忆漏洞原理。

##### 1.3.7.8 `agent/prompts/system_prompts.py`

集中管理所有 Agent 的系统提示词与工具使用规范（`TOOL_USAGE_GUIDE`）。修改项 2 里 Recon prompt 的收紧就在这里改。

##### 1.3.7.9 `agent/streaming/`

| 文件 | 作用 |
|---|---|
| `stream_handler.py` | 把 LangGraph/内部事件流转成前端能消费的 SSE 事件 |
| `token_streamer.py` | LLM token 级流式输出 |
| `tool_stream.py` | 工具调用（输入、执行、输出）流式展示 |

##### 1.3.7.10 `agent/telemetry/tracer.py`

审计过程的可观测性 tracer：每个 Agent / 每次工具调用一个 span。

### 1.4 `backend/tests/`

pytest 测试集合。命名清晰：`test_agent_*.py` 覆盖 core 子模块，`test_api_*.py` 覆盖 endpoints，`test_llm_*.py` 覆盖 LLM 抽象层。修改项 1 的 URL 解析改动最好把 `test_scanner_utils.py`（现存）扩到覆盖 `/tree/`、`/commit/` 等新形态。

### 1.5 `backend/scripts/` / `backend/static/` / `backend/uploads/`

| 目录 | 作用 |
|---|---|
| `scripts/` | 后端独立跑的运维脚本（数据回填/清理） |
| `static/` | 生成的报告静态资源、报告模板资源 |
| `uploads/` | 用户 ZIP 上传后的存储目录（挂 Docker volume 持久化） |

---

## 2. `frontend/` —— React 前端

### 2.1 顶层配置

| 文件 | 作用 |
|---|---|
| `Dockerfile` / `docker-entrypoint.sh` / `nginx.conf` | 构建 + Nginx 托管 |
| `vite.config.ts` / `vitest.config.ts` | 构建 & 测试 |
| `tsconfig*.json` | TypeScript 编译配置 |
| `tailwind.config.js` / `postcss.config.js` | 样式 |
| `components.json` | shadcn/ui 组件生成配置 |
| `package.json` / `pnpm-lock.yaml` | 依赖 |
| `index.html` | Vite 入口 HTML |

### 2.2 `frontend/src/` 主要目录

```
src/
├─ app/                       ← 应用外壳
│  ├─ main.tsx               ← ReactDOM 入口
│  ├─ App.tsx                ← 顶层布局
│  ├─ routes.tsx             ← 路由表
│  └─ ProtectedRoute.tsx     ← 登录守卫
├─ pages/                     ← 页面级组件（对应一个个路由）
├─ components/                ← 可复用组件（按域分子目录）
├─ features/                  ← 面向业务的服务/hook 组合
├─ shared/                    ← 跨页面通用工具
├─ hooks/useAgentStream.ts    ← 订阅 Agent SSE 的 hook
├─ assets/                    ← 静态资源
└─ test/                      ← 前端测试
```

#### 2.2.1 `pages/` —— 页面

| 页面 | 说明 |
|---|---|
| `Login.tsx` / `Register.tsx` / `Account.tsx` | 登录/注册/账户 |
| `Dashboard.tsx` | 主控制台 |
| `AdminDashboard.tsx` | 管理员视图 |
| `Projects.tsx` / `ProjectDetail.tsx` / `project-detail/` / `projectDetail/` | 项目列表 + 详情 |
| `InstantAnalysis.tsx` | 即时分析（粘贴代码秒级返回） |
| `AuditTasks.tsx` / `TaskDetail.tsx` | 普通扫描任务列表 & 详情 |
| `AgentAudit/` | **Agent 深度审计相关页面**（审计流日志、可视化、报告） |
| `AuditRules.tsx` / `prompt-manager/` / `PromptManager.tsx` | 规则包 & 提示词模板管理 |
| `RecycleBin.tsx` | 回收站 |
| `NotFound.tsx` | 404 |

#### 2.2.2 `components/` —— 组件库

按域分：
- `agent/` — Agent 相关组件（`AgentModeSelector.tsx`、`CreateAgentTaskDialog.tsx`、`EmbeddingConfig.tsx`）
- `analysis/` — 分析结果展示
- `audit/` — 审计详情
- `database/` — 数据备份
- `debug/` — 调试面板
- `layout/` — 布局壳（侧边栏、面包屑等）
- `reports/` — 报告渲染
- `system/` — 系统管理
- `common/` — 通用（弹窗、Loading）
- `ui/` — **shadcn/ui 基础原子组件**（button/input/dialog/table/… 共几十个）

`components/ui/branch-selector.tsx` —— 修改项 1 里"版本锚定显示"的入口组件。

#### 2.2.3 `features/`

按业务领域分组的服务代码（`analysis/services/`、`projects/services/`、`reports/services/`），页面调用它们，它们再调 `shared/api/`。

#### 2.2.4 `shared/`

| 子目录 | 作用 |
|---|---|
| `api/` | 后端 API 客户端封装（`agentTasks.ts`、`agentStream.ts`、`rules.ts`、`prompts.ts`、`sshKeys.ts`、`database.ts`、`serverClient.ts`） |
| `services/taskControl.ts` | 任务取消 / 心跳等控制通道 |
| `hooks/` | 跨页面 hook |
| `context/` | React Context |
| `config/` / `constants/` | 常量与配置 |
| `types/` | 全局 TS 类型 |
| `utils/` | 工具函数 |

#### 2.2.5 `hooks/useAgentStream.ts`

订阅 `GET /api/v1/agent-tasks/{id}/stream` 的 SSE，前端"审计流日志页"实时渲染就靠它。

---

## 3. `docker/` —— 沙箱镜像

```
docker/sandbox/
├─ Dockerfile      ← deepaudit/sandbox 镜像；修改项 3 要在此加 gcc/clang/asan/valgrind/afl++/cppcheck/flawfinder
├─ build.sh        ← 构建脚本
└─ seccomp.json    ← 沙箱 seccomp 白名单（限制系统调用）
```

沙箱镜像默认 tag 名 `deepaudit/sandbox:latest`，`docker-compose.yml` 里 backend 服务通过挂 docker.sock 起子容器时会用它。

---

## 4. `docs/` —— 官方文档

| 文档 | 内容 |
|---|---|
| `ARCHITECTURE.md` | 系统总体架构（顶层） |
| `AGENT_AUDIT.md` | Agent 审计使用手册 |
| `AGENT_AUDIT_ARCHITECTURE.md` | Agent 内部架构（Orchestrator/Recon/Analysis/Verification 协作图） |
| `AGENT_DEPLOYMENT_CHECKLIST.md` | Agent 上线部署清单 |
| `DEPLOYMENT.md` | 通用部署 |
| `CONFIGURATION.md` | 各种配置项说明 |
| `LLM_PROVIDERS.md` | 支持的 LLM provider 列表 |
| `SECURITY_TOOLS_SETUP.md` | 外部安全工具（Semgrep/Bandit/…）安装指南 |
| `FAQ.md` | 常见问题 |
| `PAPER_ARCHITECTURE.md` | 论文版架构描述 |
| `audit_report_*.html` | 一份完整审计报告示例（HTML 版） |
| `images/` | 文档配图 |

---

## 5. `rules/`

`SeletItem.yml` —— 一个规则包示例。项目本身规则主要靠数据库里 `audit_rules` 表 + Semgrep 规则集，这个 YAML 只是模板。

---

## 6. `scripts/` —— 一次性脚本

| 文件 | 作用 |
|---|---|
| `check-setup.js` | Node 侧环境检查 |
| `setup.js` / `setup.sh` / `setup.bat` | 首次部署交互式安装（跨平台三份） |
| `setup_security_tools.sh` / `.bat` / `.ps1` | 装 Semgrep / Bandit / Gitleaks / OSV-Scanner 等外部工具（跨平台三份） |
| `release.sh` | 发版脚本 |

---

## 7. `supabase/migrations/`

Supabase 版本的数据库迁移。实际部署走 alembic + PostgreSQL，这里只是备选后端，可忽略。

---

## 8. 顶层运维文件

| 文件 | 作用 |
|---|---|
| `docker-compose.yml` | 主编排：`db(postgres) / redis / backend / frontend / adminer / sandbox` 六个服务 |
| `docker-compose.override.yml` | 本地开发：源码 bind mount、放开热重载端口 |
| `docker-compose.prod.yml` | 生产用（去掉 override 的开发挂载） |
| `docker-compose.prod.cn.yml` | 生产 + 国内镜像加速 |
| `sgconfig.yml` | Semgrep 全局配置（沙箱里的 semgrep_scan 会 pick up） |
| `tools.txt` | 需要在环境里装的外部安全工具清单 |
| `CVEList.md` | README 里挂的已知 CVE 复现记录 |
| `README.md` / `README_EN.md` | 项目说明（中英双语） |
| `CHANGELOG.md` / `CONTRIBUTING.md` / `DISCLAIMER.md` / `SECURITY.md` / `LICENSE` | 常规元信息 |

---

## 9. 修改项 → 涉及文件速查

| 修改项（见 `deepaudit修改文档.md`） | 主要落点 |
|---|---|
| ①URL 深度解析（tag/commit） | `backend/app/utils/repo_utils.py`、`backend/app/services/scanner.py`、`backend/app/api/v1/endpoints/projects.py`、`backend/app/models/project.py`（加字段）、`backend/alembic/versions/`（迁移）、`frontend/src/components/ui/branch-selector.tsx`、`frontend/src/shared/api/` |
| ②SCA 强制前置 | 新增 `backend/app/services/agent/stages/preflight.py`；改 `agents/orchestrator.py`、`agents/recon.py`、`agent/prompts/system_prompts.py`；复用 `tools/external_tools.py` |
| ③C/C++ 动态验证 | 新增 `backend/app/services/agent/tools/sandbox_c.py`、`tools/fuzz_tool.py`；改 `tools/sandbox_language.py`（注册进 `UniversalCodeTestTool`）；改 `docker/sandbox/Dockerfile`；改 `agents/verification.py` 提示词 |
| ④低置信度回压 | 新增 `backend/app/services/agent/agents/refinement.py`；改 `agents/orchestrator.py`、`services/report_generator.py` |
| ⑤证据链结构化 | 新增 `backend/app/services/agent/evidence_chain.py`（5 字段提取 + 完整性评分 + Markdown 渲染）；改 `api/v1/endpoints/agent_tasks.py`（存 evidence_chain 到 finding_metadata、报告安全网补渲） |
| ⑥增量扫描缓存 | 改 `services/scanner.py`、`services/rag/indexer.py`；新增 Redis key 策略；加接口 `endpoints/projects.py` |
| ⑦双盲验证 | 拆 `agents/verification.py` 为 A/B，加 `mode=dynamic/static`；改 `agents/orchestrator.py`（`_select_cross_review_targets` 筛 HIGH/CRITICAL 双盲、MEDIUM 单侧 A 验证 + `_arbitrate` 规则表仲裁）；改 `models/agent_task.py` 加 `verdict`、`cross_review`；改 `evidence_chain.py`（渲染双盲/单侧标签） |
| ⑧SAST 前哨 & 轻量 taint | 扩 `tools/external_tools.py`；新增 `tools/trace_data_flow.py`；改 `stages/preflight.py` |

---

## 10. 阅读顺序建议

如果你是队里第一次接手代码的成员，按下面顺序读能最快建立整体印象：

1. `README.md` + `docs/ARCHITECTURE.md` —— 项目定位
2. `docs/AGENT_AUDIT_ARCHITECTURE.md` —— 四种 Agent 的协作图
3. `backend/main.py` → `backend/app/api/v1/api.py` → `backend/app/api/v1/endpoints/agent_tasks.py` —— 一次 Agent 审计请求的入口
4. `backend/app/services/agent/agents/orchestrator.py` → `recon.py` → `analysis.py` → `verification.py` —— 主流程
5. `backend/app/services/agent/tools/` 里挑 `file_tool.py` + `external_tools.py` + `sandbox_tool.py` 三份看，其它工具都是同一套 `AgentTool` 抽象派生的
6. `backend/app/models/agent_task.py` —— 数据表结构，看完就知道 Agent 状态机全貌
7. 最后 `frontend/src/pages/AgentAudit/` + `hooks/useAgentStream.ts` —— 前端如何消费后端 SSE
