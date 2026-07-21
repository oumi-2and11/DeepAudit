# DeepAudit 运行文档

Windows 11 + Docker Desktop 环境。分两部分：**部署运行**、**使用与接口说明**。

---

# 第一部分：部署运行

## 1. 前置条件

- Docker Desktop 已安装并启动（右下角小鲸鱼图标绿色）
- 打开 PowerShell 或 Git Bash（下文以 PowerShell 为例）

## 2. Docker 镜像加速

Docker Desktop → Settings → Docker Engine，替换为：

```json
{
  "registry-mirrors": [
    "https://docker.1ms.run",
    "https://dockerproxy.com",
    "https://hub.rat.dev"
  ],
  "experimental": false
}
```

Apply & Restart。

## 3. 进入项目目录

```powershell
cd D:\网络空间安全综合实验\DeepAudit
```

## 4. 拉沙箱镜像并打 tag

```powershell
docker pull ghcr.nju.edu.cn/lintsinghua/deepaudit-sandbox:latest
docker tag ghcr.nju.edu.cn/lintsinghua/deepaudit-sandbox:latest deepaudit/sandbox:latest
```

约 4.5 GB，网络慢的话等 10 分钟。

## 5. 确认 backend/.env 存在

`backend/.env` 是必需文件（compose 在 `env_file:` 里强制引用）。已经建好并做过如下修改：
- LLM/EMBEDDING 字段全部留空（改为在 admin 页面配置）
- 数据库/Redis/沙箱/JWT 等基础设施变量保留

如果这个文件不存在，从模板复制一份：
```powershell
copy backend\env.example backend\.env
```
然后打开 `backend\.env`，把 LLM_* 和 EMBEDDING_* 那几行的值清空。

## 6. 修复换行符（一次性）

Windows Git 会把 `.sh` 文件转成 CRLF，导致 Linux 容器执行时报 `no such file or directory`。用 Git Bash 跑一次：

```bash
cd /d/网络空间安全综合实验/DeepAudit
sed -i 's/\r$//' frontend/docker-entrypoint.sh backend/docker-entrypoint.sh
```

已经建好 `.gitattributes` 防止以后再被转回来。

## 7. 启动全部服务

```powershell
docker compose up -d --build
```

首次构建 10-20 分钟：
- 拉 postgres/redis/nginx/python/node 基础镜像
- 构建 backend 镜像（装 Python 依赖）
- 构建 frontend 镜像（pnpm build）
- 启动服务，自动跑数据库 migration

## 8. 验证服务状态

```powershell
docker compose ps
```

预期看到：

| 服务 | 状态 |
| --- | --- |
| deepaudit-db-1 | Up (healthy) |
| deepaudit-redis-1 | Up (healthy) |
| deepaudit-backend-1 | Up |
| deepaudit-frontend-1 | Up |
| deepaudit-adminer-1 | Up |
| deepaudit-sandbox-1 | **Exited (0)** ← 正常，这是占位服务 |

看后端日志确认就绪：
```powershell
docker compose logs backend --tail=20
```
看到 `Application startup complete.` 即可。

## 9. 打开浏览器

| 地址 | 用途 |
| --- | --- |
| http://localhost:3000 | 前端 UI |
| http://localhost:8000/docs | Swagger API 文档 |
| http://localhost:8081 | Adminer 数据库可视化（可选） |

**登录**：`demo@example.com` / `demo123`

## 10. 配置 LLM（重要）

**LLM 配置在 Web 页面完成，不在 `.env`**。原因：DeepAudit 的合并逻辑是 `DB(admin) > .env > 默认`，`.env` 里 LLM 已清空以避免覆盖 admin 的正确配置。

登录后 → **系统管理 / Admin** → **大模型配置**：

**用 DeepSeek 官方 API 举例**：

| 字段 | 值 |
| --- | --- |
| Provider | DeepSeek |
| API Key | `sk-xxxxxxxx`（DeepSeek 官网申请） |
| Base URL | **留空** |
| Model | `deepseek-chat` |
| Temperature | 0.1 |
| Max Tokens | 4096 |

点【测试连接】→ 显示成功 → 点【保存】。

保存后不用重启后端，直接使用。

## 11. 快速验证（即时分析）

侧边栏 → **即时分析** → 粘贴：

```python
import os
def run(user_input):
    os.system("ping " + user_input)
```

点分析。5-15 秒后应该看到命令注入被识别，即部署完成。

---

## 附：常用运维命令

```powershell
# 查看状态
docker compose ps

# 查看日志（实时）
docker compose logs -f backend

# 只重启后端（改代码后）
docker compose restart backend

# 让 .env 修改生效（重启不够，必须重建容器）
docker compose up -d --force-recreate backend

# 停止全部（保留数据）
docker compose down

# 停止并清空数据卷（重置数据库）
docker compose down -v

# 进后端容器 shell
docker compose exec backend sh

# 进数据库
docker compose exec db psql -U postgres -d deepaudit

# 查看当前 admin 保存的 LLM 配置
docker compose exec db psql -U postgres -d deepaudit -c "SELECT llm_config FROM user_configs;"
```

## 附：排错关键点

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| frontend 一直 restart，日志 `exec /docker-entrypoint.sh: no such file or directory` | Windows CRLF 换行 | 见步骤 6 |
| backend 401 `LiteLLM (openai) API 认证失败` | admin 里配的是别的 provider，但代码里 provider 显示 openai | 说明 `.env` 里 provider 还有值在覆盖，清空 `.env` 的 LLM_* 字段后 `--force-recreate backend` |
| 报 `deepseek-v4-flash` 找不到 | 这是方舟平台的模型别名，DeepSeek 官方不认 | admin 里 Model 改成 `deepseek-chat` |
| `.env` 改了但不生效 | `docker compose restart` 不重载 env_file | 用 `docker compose up -d --force-recreate backend` |
| 沙箱镜像找不到 | 步骤 4 没做或 tag 不对 | 重跑步骤 4 |
| Agent 审计走到 RAG 报错 | Embedding 未配置 | admin → 嵌入模型配置，或用 Ollama 本地：装 Ollama + `ollama pull nomic-embed-text`，Base URL 填 `http://host.docker.internal:11434/v1` |

## 12.修改代码后重启

万一自动 reload 卡住了

Windows + Docker Desktop + WSL2 组合下，偶尔会出现 --reload 收不到文件事件（文件系统穿透层的锅）。表现是：保存了 .py
但日志里没 Reloading...。

 兜底 3 条命令，越往下越重：

```
  # 1. 温柔：让 uvicorn 进程重启一次（保留容器）
  docker compose restart backend

  # 2. 中等：重建容器（保留镜像）—— 改了 compose.yml 后必用
  docker compose up -d --force-recreate backend

  # 3. 大锤：重打镜像 + 重建容器 —— 改了 Dockerfile / requirements.txt 后必用
  docker compose up -d --build backend
```

## 13.清缓存

下面的命令让 Redis 去把所有键名（Key）符合 `dascache:xxx` 规则的缓存全部找出来，删除：

```sh
docker exec deepaudit-redis-1 redis-cli --scan --pattern 'dascache:*' | ForEach-Object { docker exec -i deepaudit-redis-1 redis-cli del $_ }
```



---

# 第二部分：使用方法

## A. 三种审计模式

| 模式 | 用途 | 耗时 | 需要沙箱 |
| --- | --- | --- | --- |
| **即时分析** | 粘贴代码片段，秒级返回 | 5-30 秒 | 否 |
| **项目扫描** | ZIP/GitHub 导入项目，五维静态检测 | 5-30 分钟 | 否 |
| **Agent 深度审计** | Multi-Agent 协作 + 沙箱 PoC 验证 | 15 分钟-2 小时 | 是 |

## B. 三种典型工作流

### B.1 快速代码片段分析

1. 登录 → 侧边栏 **即时分析**
2. 粘贴代码，选语言
3. 点【开始分析】
4. 结果直接在页面显示，可导出 PDF

**适用**：老师课上给一段代码问是否有漏洞、写了新函数想快速自查。

### B.2 项目扫描（普通模式）

1. **项目管理** → **新建项目**
2. 三种导入方式：
   - **GitHub URL**：粘贴 `https://github.com/xxx/yyy`
   - **上传 ZIP**：直接拖压缩包
   - **本地路径**：填服务器可访问的路径
3. 项目创建后 → 点【发起扫描】
4. 选扫描维度：Bug / 安全 / 性能 / 风格 / 可维护性
5. 提交，等结果

**适用**：想快速给一个项目出五维体检报告，不需要 PoC。

### B.3 Agent 深度审计（核心功能）

1. **项目管理** → 选一个项目
2. 点【发起 Agent 审计】
3. 勾选漏洞类型：SQL 注入 / 命令注入 / 路径遍历 / 硬编码密钥 / XSS / SSRF / XXE / 反序列化 等
4. 提交后进 **审计流日志页**，可以实时看到 4 个 Agent 协作：
   - **Orchestrator**：分派任务
   - **Recon**：识别技术栈和攻击面
   - **Analysis**：分析代码找漏洞
   - **Verification**：起沙箱容器跑 PoC
5. 结束后可查看/导出报告（PDF / Markdown / JSON）

**适用**：真正做深度审计、要 PoC 证据、给课程作业跑 baseline 数据。

## C. 推荐测试项目（从小到大）

| 项目 | 链接 | 耗时 | 说明 |
| --- | --- | --- | --- |
| Vulnerable-Flask-App | https://github.com/we45/Vulnerable-Flask-App | 5 分钟 | 最小，快速验证链路 |
| NodeGoat | https://github.com/OWASP/NodeGoat | 15 分钟 | Node.js 靶场 |
| DVWA | https://github.com/digininja/DVWA | 15 分钟 | PHP 经典 |
| maccms v10 | 课程要求 | 1 小时+ | 大项目，正式扫用 |
| openvpn | 课程要求 | 2 小时+ | C 语言基础设施 |

## D. 报告导出

在扫描详情或 Agent 审计结果页面：
- **PDF**：可打印，适合交作业
- **Markdown**：可 diff、可版本控制
- **JSON**：结构化数据，可批量处理做统计

## 对于不同版本的仓库地址：

在 DeepAudit 里怎么用

  方式 A（推荐）：直接给 GitHub URL

  在 DeepAudit 建新项目时选【GitHub URL】，填：
  https://github.com/pallets/flask

  创建后进项目详情，会有【分支】选择——把分支/tag 选成 2.0.0，然后发起 Agent 审计。

---

# 第三部分：接口说明

Web UI 通过 REST + SSE 调用后端。所有接口在 http://localhost:8000/docs 有 Swagger 可交互测试。前缀：`/api/v1`。

## 认证

先登录拿 token，后续所有接口都要带 `Authorization: Bearer <token>`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | 登录（body: `{email, password}`），返回 JWT |
| POST | `/api/v1/auth/register` | 注册 |

## 用户配置（LLM 配置在这里存/读）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/config/defaults` | 拿默认配置模板 |
| GET | `/api/v1/config/me` | 拿当前用户的配置 |
| PUT | `/api/v1/config/me` | 保存/更新当前用户配置（admin 页保存走这个） |
| DELETE | `/api/v1/config/me` | 重置为默认 |
| POST | `/api/v1/config/test-llm` | 测试 LLM 连通性（admin 页"测试连接"按钮） |
| GET | `/api/v1/config/llm-providers` | 拿支持的 provider 列表 |

## 项目管理

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/projects/` | 新建项目 |
| GET | `/api/v1/projects/` | 项目列表 |
| GET | `/api/v1/projects/stats` | 项目统计 |
| GET | `/api/v1/projects/{id}` | 单个项目详情 |
| PUT | `/api/v1/projects/{id}` | 更新项目 |
| DELETE | `/api/v1/projects/{id}` | 删除项目 |
| POST | `/api/v1/projects/{id}/restore` | 恢复已删除 |
| GET | `/api/v1/projects/{id}/files` | 拿项目文件树 |
| POST | `/api/v1/projects/{id}/scan` | 对项目发起普通扫描 |
| POST | `/api/v1/projects/{id}/zip` | 上传 ZIP 关联到项目 |
| GET | `/api/v1/projects/{id}/branches` | 拿 Git 分支列表 |

## 扫描（普通模式）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/scan/upload-zip` | 上传 ZIP 触发扫描 |
| POST | `/api/v1/scan/scan-stored-zip` | 扫已上传的 ZIP |
| POST | `/api/v1/scan/instant` | **即时分析**（body: `{code, language, prompt_template?}`） |
| GET | `/api/v1/scan/instant/history` | 即时分析历史 |
| GET | `/api/v1/scan/instant/history/{id}/report/pdf` | 导出 PDF |
| DELETE | `/api/v1/scan/instant/history/{id}` | 删除单条 |
| DELETE | `/api/v1/scan/instant/history` | 清空历史 |

## Agent 深度审计（核心）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/agent-tasks/` | 发起 Agent 审计（body: `{project_id, vulnerability_types[], ...}`） |
| GET | `/api/v1/agent-tasks/` | 任务列表 |
| GET | `/api/v1/agent-tasks/{id}` | 任务详情 |
| POST | `/api/v1/agent-tasks/{id}/cancel` | 取消任务 |
| **GET** | **`/api/v1/agent-tasks/{id}/stream`** | **SSE 实时事件流**（审计流日志页用它） |
| GET | `/api/v1/agent-tasks/{id}/events` | 事件流（分页拉取） |
| GET | `/api/v1/agent-tasks/{id}/events/list` | 事件列表 |
| GET | `/api/v1/agent-tasks/{id}/findings` | 找到的漏洞列表 |
| PATCH | `/api/v1/agent-tasks/{id}/findings/{fid}` | 修改单个漏洞（标记误报等） |
| GET | `/api/v1/agent-tasks/{id}/summary` | 任务摘要 |
| GET | `/api/v1/agent-tasks/{id}/agent-tree` | Agent 协作树（可视化用） |
| GET | `/api/v1/agent-tasks/{id}/checkpoints` | 检查点列表 |
| GET | `/api/v1/agent-tasks/{id}/report` | 导出报告 |

## 规则和模板

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/rules/` | 审计规则列表（OWASP Top 10 + 自定义） |
| GET | `/api/v1/prompts/` | 提示词模板 |

## 嵌入模型

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/PUT | `/api/v1/embedding/...` | Embedding 相关配置（RAG 用） |

## 数据管理（备份/恢复）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/database/export` | 导出所有数据为 JSON |
| POST | `/api/v1/database/import` | 从 JSON 恢复 |
| DELETE | `/api/v1/database/clear` | 清空数据（谨慎） |
| GET | `/api/v1/database/health` | 数据库健康检查 |

## Git 凭证

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST/DELETE | `/api/v1/ssh-keys/` | 管理 SSH Key（拉私有仓用） |

## SSE 流式接口的用法

Agent 审计的实时日志通过 SSE 推送，`curl` 演示：

```bash
curl -N -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/agent-tasks/<task_id>/stream
```

响应格式（每行一个事件）：

```
data: {"type":"agent_start","actor":"orchestrator","ts":"..."}
data: {"type":"tool_call","tool":"semgrep","input":{...}}
data: {"type":"finding","finding":{...}}
data: {"type":"agent_end","actor":"verification"}
```

前端"审计流日志"页就是订阅这个流实时渲染的。

## 用 Swagger 直接调试

http://localhost:8000/docs

1. 点右上角【Authorize】
2. 用 `/api/v1/auth/login` 拿 token，填进去
3. 任何接口都能点【Try it out】直接调，不用写代码

# 第四部分：DeepAudit缺陷

---

## 1、DeepAudit 的分支识别有缺陷

  - 用户在 URL 里明确写了 /tree/2.0.0
  - DeepAudit 无视 tag 信息，用了 default branch
  - 这是 DeepAudit 的一个明确 bug

  你自研系统可以主打：正确解析 URL 里的 tag/commit hash/tree/blob 路径，让用户导入什么就扫什么。这就是一个具体、可演示的差异化。

## 2、从 DeepAudit 的架构看，它有做 SCA 的能力但没触发：

![image-20260707174216193](D:\网络空间安全综合实验\DeepAudit运行文档.assets\image-20260707174216193.png)

  Recon Agent 应该在初期扫 requirements.txt / setup.py 触发 osv_scanner，但这次 91 次工具调用全花在 read_file / search_code
  里翻源码。这是 Agent 编排的失误——没走 SCA 路径。

* **SCA 路径（快、准、成本低）：** 直接去读项目里的依赖配置文件（比如 Python 的 `requirements.txt`、`setup.py`，或者是 Node.js 的 `package.json`）。拿到这些列表后，直接扔给 **osv-scanner**（一款专门的 SCA 工具）去查漏洞数据库。如果命中，马上就能知道哪个第三方库有漏洞。
* **SAST / 源码审计路径（慢、耗资源）：** 一行行去读业务源码（通过 `read_file` 或 `search_code`），靠人工逻辑或静态分析去分析代码逻辑漏洞（如 SQL 注入、越权等）。

## 3、单一智能体验证

- 单一 Verification Agent 一票通过/否决，本质上是"另一个 LLM 说是就是"，仍然是幻觉链条。
- 选题里 5 个对标项目中，AgentStalker、ESAA-Security 明确提到"证据裁决"、"事件溯源确定性流水线"。
