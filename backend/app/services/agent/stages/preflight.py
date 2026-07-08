"""
Preflight stage — 改进项 2 的核心。

在 Recon Agent 之前，强制跑一次 SCA / Secrets / SAST 三件套。目的是把
"已知的、确定性的"漏洞发现从 LLM 决策路径上剥离出来，避免 Recon 花大量
token 从零手翻依赖清单（见 DeepAudit运行文档 §4.2）。

设计约束（**必须遵守**，避免引入冗余）：
1. 不新增数据库字段/迁移；结果通过 input_data / handoff 透传即可
2. 不新增 phase 枚举；复用 AgentTaskPhase.RECONNAISSANCE
3. 不改工具类签名；直接复用 external_tools.py 里已有的
   OSVScannerTool / SemgrepTool / GitleaksTool
4. 不做 LLM 调用；本模块是纯确定性流水线
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# manifest 白名单：命中任意一条就认为项目有依赖清单，值得跑 SCA
# 顺序无关；集合成员用 os.path.basename() 匹配。
# ---------------------------------------------------------------------------
_MANIFEST_FILES = frozenset({
    # Python
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    # Node / JS
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    # Go
    "go.mod", "go.sum",
    # Java / Kotlin
    "pom.xml", "build.gradle", "build.gradle.kts",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # PHP
    "composer.json", "composer.lock",
    # Ruby
    "Gemfile", "Gemfile.lock",
})

# 深度：只在 project_root 及一层子目录内找 manifest。够用，避免遍历海量文件。
_MANIFEST_SCAN_MAX_DEPTH = 2


@dataclass
class PreflightResult:
    """
    结构化前置结果。作为 dict 通过 input_data / TaskHandoff 传给下游 Agent。

    字段全部可为空——即使工具执行失败，preflight 也不阻塞主流程，只挂 warning。
    """
    has_manifest: bool = False
    manifests: List[str] = field(default_factory=list)  # 相对路径
    sca: Dict[str, Any] = field(default_factory=lambda: {"tool": "osv-scanner", "count": 0, "vulnerabilities": []})
    secrets: Dict[str, Any] = field(default_factory=lambda: {"tool": "gitleaks", "count": 0, "leaks": []})
    sast: Dict[str, Any] = field(default_factory=lambda: {"tool": "semgrep", "count": 0, "findings": []})
    # 🔥 仓库自识别：项目本身是不是某个"已发布库的历史版本"（如 Flask 2.0.0）
    self_identity: Dict[str, Any] = field(default_factory=lambda: {
        "name": None, "version": None, "ecosystem": None,
        "manifest_file": None, "vulnerabilities": [],
    })
    warnings: List[str] = field(default_factory=list)
    summary_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_manifest": self.has_manifest,
            "manifests": self.manifests,
            "sca": self.sca,
            "secrets": self.secrets,
            "sast": self.sast,
            "self_identity": self.self_identity,
            "warnings": self.warnings,
            "summary_text": self.summary_text,
        }


def _find_manifests(project_root: str) -> List[str]:
    """扫描根 + 一层子目录，返回命中的 manifest 相对路径。"""
    hits: List[str] = []
    try:
        root_abs = os.path.abspath(project_root)
        for dirpath, dirnames, filenames in os.walk(root_abs):
            # 深度控制
            depth = os.path.relpath(dirpath, root_abs).count(os.sep) + (0 if dirpath == root_abs else 1)
            if depth > _MANIFEST_SCAN_MAX_DEPTH:
                dirnames[:] = []
                continue
            # 跳过明显的噪声目录
            dirnames[:] = [d for d in dirnames if d not in {
                ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", ".tox"
            }]
            for fn in filenames:
                if fn in _MANIFEST_FILES:
                    hits.append(os.path.relpath(os.path.join(dirpath, fn), root_abs))
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[preflight] manifest 扫描异常: {e}")
    return hits


# ============================================================================
# 仓库自识别 (Self-CVE lookup) —— 改进项 2 补丁
#
# 场景：扫描目标本身**就是**一个已发布库的历史 tag（Flask 2.0.0 / log4j 2.14.1
# / fastjson 1.2.24 / maccms10 / ThinkPHP...）。此时传统 SCA 因为没有锁文件、
# 也不会把项目自己当作"依赖"，会漏掉——但这个 repo 版本本身可能挂着一堆 CVE。
#
# 做法：从项目自己的 manifest 里抽 (name, version)，直查 OSV API。
# ============================================================================

_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT = 8.0
_PLACEHOLDER_VERSIONS = frozenset({
    "", "0.0.0", "0.0.1", "0.1.0", "1.0.0-dev", "0.0.0-dev",
    "dev", "master", "main", "head", "unknown",
})


def _read_text_safe(path: str, limit: int = 200_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(limit)
    except Exception:  # noqa: BLE001
        return None


def _extract_version_from_python_module(project_root: str, package_name: str) -> Optional[str]:
    """setup.cfg 常见写法 version = attr: flask.__version__，需要去模块里读。"""
    if not package_name:
        return None
    candidates = [
        os.path.join(project_root, "src", package_name, "__init__.py"),
        os.path.join(project_root, package_name, "__init__.py"),
        os.path.join(project_root, "src", package_name.lower(), "__init__.py"),
        os.path.join(project_root, package_name.lower(), "__init__.py"),
    ]
    for p in candidates:
        text = _read_text_safe(p, limit=20_000)
        if not text:
            continue
        m = re.search(r'^\s*__version__\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return None


def _identify_self_from_python(project_root: str) -> Optional[Tuple[str, str, str, str]]:
    # setup.cfg
    cfg_path = os.path.join(project_root, "setup.cfg")
    text = _read_text_safe(cfg_path)
    if text:
        name_m = re.search(r'^\s*name\s*=\s*(\S+)', text, re.MULTILINE)
        ver_m = re.search(r'^\s*version\s*=\s*(.+)$', text, re.MULTILINE)
        if name_m:
            name = name_m.group(1).strip()
            version: Optional[str] = None
            if ver_m:
                raw = ver_m.group(1).strip()
                if re.match(r'^[0-9]', raw):
                    version = raw.split()[0]
                elif raw.lower().startswith("attr:"):
                    dotted = raw.split(":", 1)[1].strip()
                    pkg = dotted.split(".")[0]
                    version = _extract_version_from_python_module(project_root, pkg)
                elif raw.lower().startswith("file:"):
                    rel = raw.split(":", 1)[1].strip()
                    ftext = _read_text_safe(os.path.join(project_root, rel), limit=200)
                    if ftext:
                        version = ftext.strip().splitlines()[0].strip()
            if not version:
                version = _extract_version_from_python_module(project_root, name)
            if name and version:
                return (name, version, "PyPI", "setup.cfg")

    # pyproject.toml
    pp_path = os.path.join(project_root, "pyproject.toml")
    text = _read_text_safe(pp_path)
    if text:
        for section_header in (r'\[project\]', r'\[tool\.poetry\]'):
            m_sec = re.search(section_header + r'(.*?)(?=\n\[|\Z)', text, re.DOTALL)
            if not m_sec:
                continue
            body = m_sec.group(1)
            name_m = re.search(r'^\s*name\s*=\s*[\'"]([^\'"]+)[\'"]', body, re.MULTILINE)
            ver_m = re.search(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', body, re.MULTILINE)
            if name_m and ver_m:
                return (name_m.group(1), ver_m.group(1), "PyPI", "pyproject.toml")

    # setup.py
    sp_path = os.path.join(project_root, "setup.py")
    text = _read_text_safe(sp_path)
    if text:
        name_m = re.search(r'''name\s*=\s*['"]([^'"]+)['"]''', text)
        ver_m = re.search(r'''version\s*=\s*['"]([^'"]+)['"]''', text)
        if name_m and ver_m:
            return (name_m.group(1), ver_m.group(1), "PyPI", "setup.py")

    return None


def _identify_self_from_node(project_root: str) -> Optional[Tuple[str, str, str, str]]:
    import json as _json
    pj = os.path.join(project_root, "package.json")
    text = _read_text_safe(pj)
    if not text:
        return None
    try:
        data = _json.loads(text)
    except Exception:  # noqa: BLE001
        return None
    name = (data.get("name") or "").strip()
    version = (data.get("version") or "").strip()
    if name and version:
        return (name, version, "npm", "package.json")
    return None


def _identify_self_from_java(project_root: str) -> Optional[Tuple[str, str, str, str]]:
    pom = os.path.join(project_root, "pom.xml")
    text = _read_text_safe(pom)
    if not text:
        return None
    art_m = re.search(r'<artifactId>\s*([^<\s]+)\s*</artifactId>', text)
    grp_m = re.search(r'<groupId>\s*([^<\s]+)\s*</groupId>', text)
    ver_m = re.search(r'<version>\s*([^<\s]+)\s*</version>', text)
    if art_m and ver_m:
        name = art_m.group(1)
        if grp_m:
            name = f"{grp_m.group(1)}:{art_m.group(1)}"
        return (name, ver_m.group(1), "Maven", "pom.xml")
    return None


def _identify_self_from_php(project_root: str) -> Optional[Tuple[str, str, str, str]]:
    import json as _json
    cj = os.path.join(project_root, "composer.json")
    text = _read_text_safe(cj)
    if not text:
        return None
    try:
        data = _json.loads(text)
    except Exception:  # noqa: BLE001
        return None
    name = (data.get("name") or "").strip()
    version = (data.get("version") or "").strip()
    if name and version:
        return (name, version, "Packagist", "composer.json")
    return None


def _identify_self_from_rust(project_root: str) -> Optional[Tuple[str, str, str, str]]:
    ct = os.path.join(project_root, "Cargo.toml")
    text = _read_text_safe(ct)
    if not text:
        return None
    m_sec = re.search(r'\[package\](.*?)(?=\n\[|\Z)', text, re.DOTALL)
    if not m_sec:
        return None
    body = m_sec.group(1)
    name_m = re.search(r'^\s*name\s*=\s*[\'"]([^\'"]+)[\'"]', body, re.MULTILINE)
    ver_m = re.search(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', body, re.MULTILINE)
    if name_m and ver_m:
        return (name_m.group(1), ver_m.group(1), "crates.io", "Cargo.toml")
    return None


def _identify_project_self(project_root: str) -> Optional[Dict[str, str]]:
    """综合尝试。返回 {'name','version','ecosystem','manifest_file'} 或 None。"""
    for fn in (
        _identify_self_from_python,
        _identify_self_from_node,
        _identify_self_from_java,
        _identify_self_from_php,
        _identify_self_from_rust,
    ):
        try:
            hit = fn(project_root)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[preflight] self-identify {fn.__name__} 异常: {e}")
            continue
        if not hit:
            continue
        name, version, ecosystem, manifest = hit
        v_clean = version.strip().lstrip("vV").split("+", 1)[0]
        if v_clean.lower() in _PLACEHOLDER_VERSIONS:
            logger.info(f"[preflight] self-identify 命中 {name} 但版本占位 ({v_clean})，跳过")
            return None
        return {
            "name": name,
            "version": v_clean,
            "ecosystem": ecosystem,
            "manifest_file": manifest,
        }
    return None


async def _query_osv(name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """直查 OSV API。失败返回空列表并 warning。"""
    try:
        import httpx
    except ImportError:
        logger.warning("[preflight] httpx 不可用，跳过 OSV self-query")
        return []

    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        async with httpx.AsyncClient(timeout=_OSV_TIMEOUT) as client:
            r = await client.post(_OSV_ENDPOINT, json=payload)
            if r.status_code != 200:
                logger.warning(f"[preflight] OSV API 返回 {r.status_code}: {r.text[:200]}")
                return []
            data = r.json() or {}
            return data.get("vulns", []) or []
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[preflight] OSV API 查询失败: {e}")
        return []


def _condense_osv_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    aliases = v.get("aliases") or []
    severity = ""
    for s in v.get("severity") or []:
        if s.get("type", "").startswith("CVSS"):
            severity = s.get("score", "")
            break
    return {
        "id": v.get("id"),
        "aliases": aliases[:5],
        "summary": (v.get("summary") or "")[:300],
        "severity_score": severity,
        "references": [r.get("url") for r in (v.get("references") or [])[:3] if r.get("url")],
    }


async def _emit(event_emitter, level: str, msg: str) -> None:
    """安全 emit，允许 event_emitter 为 None。"""
    if event_emitter is None:
        logger.info(f"[preflight] {msg}")
        return
    try:
        if level == "warning":
            await event_emitter.emit_warning(msg)
        elif level == "error":
            await event_emitter.emit_error(msg)
        else:
            await event_emitter.emit_info(msg)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[preflight] event emit 失败: {e}")


def _condense_osv(raw_text: str) -> List[Dict[str, Any]]:
    """
    尝试把 OSVScannerTool 的 data 文本里出现的 CVE 提取出来（OSVScannerTool 当前
    不在 metadata 里放明细，只放 count）。这里做粗提取，防止丢信息。
    """
    import re
    vulns: List[Dict[str, Any]] = []
    if not raw_text:
        return vulns
    # 匹配 "🔴 GHSA-xxxx-xxxx" / "🔴 CVE-YYYY-NNNN" / "🔴 PYSEC-YYYY-NNN" 这种行
    ids = re.findall(r"🔴\s+([A-Z]+-[A-Za-z0-9\-]+)", raw_text)
    seen = set()
    for vid in ids:
        if vid in seen:
            continue
        seen.add(vid)
        vulns.append({"id": vid})
    return vulns


async def run_preflight(
    project_root: str,
    sandbox_manager,
    event_emitter=None,
    task_id: Optional[str] = None,
    enable_sca: bool = True,
    enable_secrets: bool = True,
    enable_sast: bool = True,
) -> Dict[str, Any]:
    """
    执行前置扫描。返回 PreflightResult.to_dict()（永远返回，不抛异常）。

    Args:
        project_root: 项目根目录（绝对路径）
        sandbox_manager: 已初始化的 SandboxManager，从 _execute_agent_task 传下来
        event_emitter: 用于前端进度显示，可为 None
        task_id: 仅用于日志

    Returns:
        {
            "has_manifest": bool,
            "manifests": [...],
            "sca": {"tool": ..., "count": N, "vulnerabilities": [...]},
            "secrets": {"tool": ..., "count": N, "leaks": [...]},
            "sast": {"tool": ..., "count": N, "findings": [...]},
            "warnings": [...],
            "summary_text": "..."
        }
    """
    # 局部导入避免循环
    from app.services.agent.tools.external_tools import (
        OSVScannerTool, GitleaksTool, SemgrepTool,
    )

    result = PreflightResult()

    if not project_root or not os.path.isdir(project_root):
        result.warnings.append(f"project_root 不存在或不是目录: {project_root}")
        result.summary_text = "Preflight 跳过：项目根目录无效。"
        return result.to_dict()

    # ----- 阶段开始事件 -----
    try:
        if event_emitter is not None:
            await event_emitter.emit_phase_start(
                "preflight",
                "🛰️ Preflight 前置扫描（SCA / Secrets / SAST）",
            )
    except Exception:  # noqa: BLE001
        pass

    # ----- 1) manifest 探测 -----
    manifests = _find_manifests(project_root)
    result.manifests = manifests
    result.has_manifest = bool(manifests)
    await _emit(event_emitter, "info",
                f"🔎 发现 {len(manifests)} 个依赖清单文件"
                + (f"：{', '.join(manifests[:5])}" if manifests else ""))

    # ----- 2) SCA (OSV) -----
    if enable_sca and result.has_manifest:
        try:
            tool = OSVScannerTool(project_root=project_root, sandbox_manager=sandbox_manager)
            osv_res = await tool._execute(target_path=".")
            if osv_res and osv_res.success:
                count = 0
                vulns: List[Dict[str, Any]] = []
                if osv_res.metadata:
                    count = int(osv_res.metadata.get("findings_count", 0) or 0)
                # OSVScannerTool 目前不把明细放 metadata，从 data 文本里粗提
                vulns = _condense_osv(osv_res.data or "")
                if not count and vulns:
                    count = len(vulns)
                result.sca = {
                    "tool": "osv-scanner",
                    "count": count,
                    "vulnerabilities": vulns,
                    "raw_summary": (osv_res.data or "")[:2000],
                }
                await _emit(event_emitter, "info", f"📋 SCA: 发现 {count} 个依赖漏洞")
            else:
                err = (osv_res.error if osv_res else "unknown") or "unknown"
                result.warnings.append(f"osv-scanner 执行失败: {err}")
                await _emit(event_emitter, "warning", f"⚠️ SCA 跳过：{err}")
        except Exception as e:  # noqa: BLE001
            result.warnings.append(f"osv-scanner 异常: {e}")
            logger.exception("[preflight] OSV failure")
    elif enable_sca:
        result.warnings.append("未发现依赖清单，跳过 SCA")
        await _emit(event_emitter, "info", "ℹ️ 未发现依赖清单文件，跳过 SCA")

    # ----- 2.5) 仓库自识别 (Self-CVE) -----
    # 补 SCA 的盲区：当前 repo 本身就是某个已发布库的历史版本时，
    # 传统 SCA 没有锁文件、也不会把项目自己算作依赖，会漏掉。
    # 这里直接从 manifest 抽 (name, version) 去问 OSV。
    if enable_sca:
        try:
            self_ident = _identify_project_self(project_root)
            if self_ident:
                await _emit(
                    event_emitter, "info",
                    f"🪪 仓库自识别：{self_ident['name']}@{self_ident['version']} "
                    f"({self_ident['ecosystem']}，来自 {self_ident['manifest_file']}), "
                    f"正在向 OSV 查询自身 CVE..."
                )
                raw = await _query_osv(
                    self_ident["name"], self_ident["version"], self_ident["ecosystem"]
                )
                condensed = [_condense_osv_vuln(v) for v in raw]
                result.self_identity = {
                    **self_ident,
                    "vulnerabilities": condensed,
                }
                await _emit(
                    event_emitter, "info",
                    f"🩺 仓库自 CVE 查询：命中 {len(condensed)} 条"
                    + (f"（样本 {', '.join(v.get('id','?') for v in condensed[:5])}）" if condensed else "")
                )
                # 合并进 result.sca.vulnerabilities：Orchestrator 兜底注入路径直接受益
                if condensed:
                    existing = list(result.sca.get("vulnerabilities") or [])
                    seen_ids = {(v or {}).get("id") for v in existing}
                    merged = existing + [v for v in condensed if v.get("id") not in seen_ids]
                    # 按 id 计算真正新增的数量（避免 SCA 已经报过又重复计）
                    added = len(merged) - len(existing)
                    result.sca["vulnerabilities"] = merged
                    result.sca["count"] = int(result.sca.get("count", 0) or 0) + added
            else:
                logger.debug("[preflight] 仓库自识别：未识别出 (name,version) 组合")
        except Exception as e:  # noqa: BLE001
            result.warnings.append(f"self-identify 异常: {e}")
            logger.exception("[preflight] self-identify failure")

    # ----- 3) Secrets (Gitleaks) -----
    if enable_secrets:
        try:
            tool = GitleaksTool(project_root=project_root, sandbox_manager=sandbox_manager)
            gl_res = await tool._execute(target_path=".")
            if gl_res and gl_res.success:
                count = int((gl_res.metadata or {}).get("findings_count", 0) or 0)
                leaks = (gl_res.metadata or {}).get("findings", []) or []
                result.secrets = {
                    "tool": "gitleaks",
                    "count": count,
                    "leaks": leaks,
                }
                await _emit(event_emitter, "info", f"🔐 Secrets: 发现 {count} 处密钥/凭据")
            else:
                err = (gl_res.error if gl_res else "unknown") or "unknown"
                result.warnings.append(f"gitleaks 执行失败: {err}")
                await _emit(event_emitter, "warning", f"⚠️ Secrets 跳过：{err}")
        except Exception as e:  # noqa: BLE001
            result.warnings.append(f"gitleaks 异常: {e}")
            logger.exception("[preflight] Gitleaks failure")

    # ----- 4) SAST (Semgrep) -----
    if enable_sast:
        try:
            tool = SemgrepTool(project_root=project_root, sandbox_manager=sandbox_manager)
            sg_res = await tool._execute(target_path=".", rules="p/security-audit")
            if sg_res and sg_res.success:
                meta = sg_res.metadata or {}
                count = int(meta.get("findings_count", 0) or 0)
                raw_findings = meta.get("findings", []) or []
                # 只保留下游 prompt 真的会用到的字段，避免污染上下文
                trimmed = []
                for f in raw_findings[:20]:
                    trimmed.append({
                        "check_id": f.get("check_id"),
                        "path": f.get("path"),
                        "line": (f.get("start") or {}).get("line"),
                        "severity": (f.get("extra") or {}).get("severity"),
                        "message": ((f.get("extra") or {}).get("message") or "")[:200],
                    })
                result.sast = {
                    "tool": "semgrep",
                    "count": count,
                    "findings": trimmed,
                }
                await _emit(event_emitter, "info", f"🔍 SAST: 发现 {count} 处 semgrep 命中")
            else:
                err = (sg_res.error if sg_res else "unknown") or "unknown"
                result.warnings.append(f"semgrep 执行失败: {err}")
                await _emit(event_emitter, "warning", f"⚠️ SAST 跳过：{err}")
        except Exception as e:  # noqa: BLE001
            result.warnings.append(f"semgrep 异常: {e}")
            logger.exception("[preflight] Semgrep failure")

    # ----- 5) 生成给 LLM 用的摘要文本 -----
    result.summary_text = _build_summary_text(result)

    await _emit(event_emitter, "info",
                f"✅ Preflight 完成：SCA={result.sca['count']}, "
                f"Secrets={result.secrets['count']}, SAST={result.sast['count']}")

    return result.to_dict()


def _build_summary_text(pf: PreflightResult) -> str:
    """构造 prompt-friendly 的自然语言摘要（不含 emoji，避免个别模型 token 浪费）。"""
    parts: List[str] = []
    parts.append("Preflight 阶段已经跑完 SCA / Secrets / SAST 三项确定性扫描，结果如下：")

    if pf.manifests:
        parts.append(f"- 依赖清单文件（{len(pf.manifests)}）：{', '.join(pf.manifests[:8])}")
    else:
        parts.append("- 依赖清单：未发现")

    # 仓库自识别
    ident = pf.self_identity or {}
    if ident.get("name") and ident.get("version"):
        self_vulns = ident.get("vulnerabilities") or []
        if self_vulns:
            ids = [v.get("id") for v in self_vulns if v.get("id")]
            parts.append(
                f"- 仓库自识别：{ident['name']}@{ident['version']} ({ident.get('ecosystem')}), "
                f"OSV 命中 {len(self_vulns)} 条 CVE"
                + (f"，样本：{', '.join(ids[:8])}" if ids else "")
            )
        else:
            parts.append(
                f"- 仓库自识别：{ident['name']}@{ident['version']} ({ident.get('ecosystem')}), "
                f"OSV 未命中"
            )

    # SCA
    sca_count = pf.sca.get("count", 0)
    if sca_count:
        vuln_ids = [v.get("id") for v in (pf.sca.get("vulnerabilities") or []) if v.get("id")]
        parts.append(f"- SCA (osv-scanner)：命中 {sca_count} 条已知漏洞"
                     + (f"，样本 ID：{', '.join(vuln_ids[:8])}" if vuln_ids else ""))
    else:
        parts.append("- SCA (osv-scanner)：0 条")

    # Secrets
    sec_count = pf.secrets.get("count", 0)
    if sec_count:
        rules = [l.get("rule") for l in (pf.secrets.get("leaks") or []) if l.get("rule")]
        parts.append(f"- Secrets (gitleaks)：命中 {sec_count} 处"
                     + (f"，样本规则：{', '.join(list(dict.fromkeys(rules))[:6])}" if rules else ""))
    else:
        parts.append("- Secrets (gitleaks)：0 条")

    # SAST
    sast_count = pf.sast.get("count", 0)
    if sast_count:
        top = pf.sast.get("findings", []) or []
        preview_lines = [
            f"    * [{f.get('severity','?')}] {f.get('check_id','?')} @ {f.get('path','?')}:{f.get('line','?')}"
            for f in top[:6]
        ]
        parts.append(f"- SAST (semgrep p/security-audit)：命中 {sast_count} 条")
        parts.extend(preview_lines)
    else:
        parts.append("- SAST (semgrep p/security-audit)：0 条")

    if pf.warnings:
        parts.append("- 执行 warning：")
        for w in pf.warnings[:5]:
            parts.append(f"    * {w}")

    parts.append("")
    parts.append("下游 Agent 请注意：不要再重复调用 osv_scan / gitleaks_scan / semgrep_scan；"
                 "对上述命中，请用 read_file / search_code 定位调用点，"
                 "并在 initial_findings 中生成对应条目（source 分别标记为 sca / secrets / sast）。")
    return "\n".join(parts)
