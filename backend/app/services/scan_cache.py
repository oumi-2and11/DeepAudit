"""
扫描缓存服务（deepaudit修改文档.md §6：差量增量扫描 & 缓存）

三级缓存 —— 全部落在 Redis，key 都以 `project_fingerprint` 做前缀，同一 commit
（或同一份文件树）第二次扫描直接命中，跳过 Preflight / Verification / 整轮 Agent。

- Preflight 缓存 key: `dascache:preflight:{fp}:v1` → run_preflight() 的返回 dict
- Finding 结果缓存 key: `dascache:findings:{fp}:v1` → 完整 findings 列表 + meta
- Verification 结果缓存 key: `dascache:verified:{fp}:{file}:{line}:{rule}` → 单条判定

指纹策略：
  1. 若项目根有 `.git`，取 `git rev-parse HEAD` 作为指纹（最快最准）
  2. 否则用 `sha256(sorted[(relpath, size)])`（不含 mtime，避免 clone 就变）

设计约束：
  - 缓存全部可失败，任何 Redis 异常都吃掉并返回 None，绝对不能阻断主流程。
  - 序列化用 JSON。value 里若含 datetime 或 set，先转成 str/list。
  - TTL 默认 7 天，够覆盖同一次课程演示反复重跑，也不会永久占内存。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ==================== 配置 ====================

_KEY_PREFIX = "dascache"
_DEFAULT_TTL = 7 * 24 * 3600  # 7 天

# 项目指纹算法版本 —— 一旦改指纹算法就 bump，历史 key 自然作废
_FP_VERSION = "v1"

# ==================== Redis 客户端（惰性单例） ====================

_client = None
_client_probed = False


def _get_client():
    """
    惰性获取 redis client。失败一次就永久标记不可用，避免每次都 socket()。
    """
    global _client, _client_probed
    if _client_probed:
        return _client
    _client_probed = True
    try:
        import redis  # type: ignore
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        c = redis.from_url(url, socket_connect_timeout=1.5, socket_timeout=2.0)
        c.ping()
        _client = c
        logger.info(f"[scan_cache] Redis client ready ({url})")
    except Exception as e:  # noqa: BLE001
        _client = None
        logger.warning(f"[scan_cache] Redis 不可用，缓存禁用: {e}")
    return _client


def is_available() -> bool:
    """外部可用于判断缓存是否可用（不可用时上游会打印一条 info 而非跑一次热身失败）"""
    return _get_client() is not None


# ==================== 指纹计算 ====================

def _git_head_sha(project_root: str) -> Optional[str]:
    """取 git HEAD 的完整 sha。失败返回 None。"""
    git_dir = os.path.join(project_root, ".git")
    if not os.path.isdir(git_dir) and not os.path.isfile(git_dir):
        return None
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0:
            sha = (out.stdout or "").strip()
            if len(sha) >= 7:
                return sha
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[scan_cache] git rev-parse 失败: {e}")
    return None


def _content_hash(project_root: str, max_files: int = 20000) -> str:
    """
    没有 .git 时的兜底：按 (relpath, size) 排序做 sha256。
    - 不含 mtime，clone 时 mtime 会变，会破坏缓存。
    - 忽略 __pycache__ / node_modules / .git 等重灾区。
    - 文件数超过 max_files 时取前 max_files 个，避免 monorepo 卡死；
      同时把总文件数也塞进 hash，让"多了几个文件"这种改动也能被检测到。
    """
    ignored = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode",
               "dist", "build", "target", ".mypy_cache", ".pytest_cache"}
    entries: List[Tuple[str, int]] = []
    total = 0
    for root, dirs, files in os.walk(project_root):
        # in-place 过滤忽略目录
        dirs[:] = [d for d in dirs if d not in ignored]
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                size = os.path.getsize(fp)
            except OSError:
                continue
            rel = os.path.relpath(fp, project_root).replace("\\", "/")
            total += 1
            if len(entries) < max_files:
                entries.append((rel, size))
    entries.sort()
    h = hashlib.sha256()
    h.update(f"total={total}\n".encode())
    for rel, size in entries:
        h.update(f"{rel}\0{size}\n".encode())
    return h.hexdigest()


def compute_project_fingerprint(project_root: str) -> Optional[str]:
    """
    计算项目指纹。返回 None 表示指纹算不出（目录不存在等），此时不应写/读缓存。
    """
    if not project_root or not os.path.isdir(project_root):
        return None
    sha = _git_head_sha(project_root)
    if sha:
        return f"git-{sha}-{_FP_VERSION}"
    try:
        h = _content_hash(project_root)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[scan_cache] 内容 hash 计算失败: {e}")
        return None
    return f"tree-{h[:32]}-{_FP_VERSION}"


# ==================== 底层 get/set ====================

def _get_json(key: str) -> Optional[Any]:
    c = _get_client()
    if c is None:
        return None
    try:
        raw = c.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[scan_cache] get 失败 key={key}: {e}")
        return None


def _set_json(key: str, value: Any, ttl: int = _DEFAULT_TTL) -> bool:
    c = _get_client()
    if c is None:
        return False
    try:
        data = json.dumps(value, ensure_ascii=False, default=str)
        c.set(key, data, ex=ttl)
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[scan_cache] set 失败 key={key}: {e}")
        return False


# ==================== Preflight 缓存 ====================

def preflight_key(fingerprint: str) -> str:
    return f"{_KEY_PREFIX}:preflight:{fingerprint}"


def get_preflight(fingerprint: str) -> Optional[Dict[str, Any]]:
    """命中返回 preflight_summary dict，未命中返回 None。"""
    if not fingerprint:
        return None
    v = _get_json(preflight_key(fingerprint))
    if v is not None:
        logger.info(f"[scan_cache] ✅ Preflight 命中 fp={fingerprint[:20]}")
    return v


def set_preflight(fingerprint: str, summary: Dict[str, Any], ttl: int = _DEFAULT_TTL) -> bool:
    if not fingerprint or not isinstance(summary, dict):
        return False
    ok = _set_json(preflight_key(fingerprint), summary, ttl=ttl)
    if ok:
        logger.info(f"[scan_cache] 💾 Preflight 已缓存 fp={fingerprint[:20]}")
    return ok


# ==================== Findings 缓存（整轮 Agent 结果） ====================

def findings_key(fingerprint: str) -> str:
    return f"{_KEY_PREFIX}:findings:{fingerprint}"


def get_findings(fingerprint: str) -> Optional[Dict[str, Any]]:
    """
    返回 {"findings": [...], "meta": {...}} 或 None。
    meta 里塞了原任务 id、生成时间等，方便在报告里打"复用自 task xxx"标注。
    """
    if not fingerprint:
        return None
    v = _get_json(findings_key(fingerprint))
    if v is not None:
        n = len(v.get("findings") or [])
        logger.info(f"[scan_cache] ✅ Findings 命中 fp={fingerprint[:20]} count={n}")
    return v


def set_findings(
    fingerprint: str,
    findings: List[Dict[str, Any]],
    meta: Optional[Dict[str, Any]] = None,
    ttl: int = _DEFAULT_TTL,
) -> bool:
    if not fingerprint:
        return False
    payload = {
        "findings": findings or [],
        "meta": meta or {},
    }
    ok = _set_json(findings_key(fingerprint), payload, ttl=ttl)
    if ok:
        logger.info(
            f"[scan_cache] 💾 Findings 已缓存 fp={fingerprint[:20]} "
            f"count={len(findings or [])}"
        )
    return ok


# ==================== 单条 Verification 判定缓存 ====================

def _norm(s: Optional[str]) -> str:
    return (s or "").strip().replace("\\", "/")


def verified_key(fingerprint: str, file_path: str, line: int, rule_id: str) -> str:
    """(commit, file, line, rule) → 该 finding 的验证判定"""
    return (
        f"{_KEY_PREFIX}:verified:{fingerprint}:"
        f"{_norm(file_path)}:{int(line or 0)}:{_norm(rule_id) or 'unknown'}"
    )


def get_verified(fingerprint: str, file_path: str, line: int, rule_id: str) -> Optional[Dict[str, Any]]:
    if not fingerprint:
        return None
    return _get_json(verified_key(fingerprint, file_path, line, rule_id))


def set_verified(
    fingerprint: str,
    file_path: str,
    line: int,
    rule_id: str,
    verdict: Dict[str, Any],
    ttl: int = _DEFAULT_TTL,
) -> bool:
    if not fingerprint:
        return False
    return _set_json(
        verified_key(fingerprint, file_path, line, rule_id),
        verdict,
        ttl=ttl,
    )


# ==================== 失效 & 调试辅助 ====================

def invalidate_project(fingerprint: str) -> int:
    """
    删掉某个指纹相关的所有缓存条目。返回删除的 key 数（Redis 不可用返回 0）。
    用途：修 bug 或规则升级后强制刷新。
    """
    c = _get_client()
    if c is None or not fingerprint:
        return 0
    n = 0
    for prefix in ("preflight", "findings", "verified"):
        pattern = f"{_KEY_PREFIX}:{prefix}:{fingerprint}*"
        try:
            for k in c.scan_iter(pattern, count=200):
                c.delete(k)
                n += 1
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[scan_cache] invalidate scan 失败 pattern={pattern}: {e}")
    if n:
        logger.info(f"[scan_cache] 🧹 已清除 {n} 条 fp={fingerprint[:20]} 缓存")
    return n


def stats() -> Dict[str, Any]:
    """轻量统计，用于 /api/v1/config/cache-status 或调试。"""
    c = _get_client()
    if c is None:
        return {"available": False}
    counts = {}
    try:
        for prefix in ("preflight", "findings", "verified"):
            n = 0
            for _ in c.scan_iter(f"{_KEY_PREFIX}:{prefix}:*", count=500):
                n += 1
            counts[prefix] = n
    except Exception as e:  # noqa: BLE001
        return {"available": True, "error": str(e)}
    return {"available": True, "counts": counts}
