from urllib.parse import urlparse
from typing import Dict, Optional, Tuple
import re


# ---------------------------------------------------------------------------
# 内部工具：识别不同托管平台在 URL 里承载 ref (分支/tag/commit) 的路径分段
# ---------------------------------------------------------------------------

# 认得的"ref 前缀分段"。命中之一，则后一段视为 ref，再后面视为仓库内路径。
# 顺序很重要：更长/更具体的前缀要先匹配（如 releases/tag 要在 tag 之前尝试）。
_REF_MARKERS_GITHUB = (
    ("releases", "tag"),   # /releases/tag/<tag>
    ("tree",),             # /tree/<ref>[/...]
    ("blob",),             # /blob/<ref>/<path>
    ("commit",),           # /commit/<sha>
    ("commits",),          # /commits/<ref>
    ("raw",),              # /raw/<ref>/<path>
)

# GitLab 常见形态。GitLab 项目路径可能带子组，且 ref 段前会有一个 "-" 分隔（新版）
# 例：/group/sub/proj/-/tree/<ref>[/...]  也支持老版无 "-" 形态
_REF_MARKERS_GITLAB = (
    ("tree",),
    ("blob",),
    ("commit",),
    ("commits",),
    ("tags",),
    ("raw",),
)

# Gitea：/<owner>/<repo>/src/branch/<ref>[/...]  /src/tag/<ref>  /src/commit/<sha>
# 也支持 /commit/<sha>, /raw/branch/<ref>/<path>
_GITEA_SRC_KIND = {"branch", "tag", "commit"}


# 40 位十六进制视为 commit sha
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _is_commit_like(ref: str) -> bool:
    """粗略识别 ref 是否像 commit sha。仅用于本地兜底猜测 ref_type，不做真实校验。"""
    return bool(_SHA_RE.match(ref)) and len(ref) in (7, 8, 10, 12, 16, 40)


def _join_rest(parts) -> Optional[str]:
    """把剩余路径拼回文件路径；空则返回 None。"""
    if not parts:
        return None
    return "/".join(parts) or None


def _extract_ref_github(path_parts):
    """
    从 GitHub 路径段中提取 (owner, repo, ref, ref_type, path_in_repo)。
    path_parts 已去掉前后空段并去 .git 后缀。至少 2 段（owner/repo）。
    """
    owner, repo = path_parts[0], path_parts[1]
    rest = path_parts[2:]

    if not rest:
        return owner, repo, None, None, None

    # /releases/tag/<tag>
    if len(rest) >= 3 and rest[0] == "releases" and rest[1] == "tag":
        return owner, repo, rest[2], "tag", _join_rest(rest[3:])

    marker = rest[0]
    # /tree/<ref>[/...]  /blob/<ref>/<path>  /commits/<ref>[/...]
    if marker in ("tree", "blob", "commits", "raw") and len(rest) >= 2:
        ref = rest[1]
        ref_type = "commit" if _is_commit_like(ref) else "ref"
        return owner, repo, ref, ref_type, _join_rest(rest[2:])

    # /commit/<sha>
    if marker == "commit" and len(rest) >= 2:
        return owner, repo, rest[1], "commit", _join_rest(rest[2:])

    # 认不出来就当没有 ref，避免误伤原有语义
    return owner, repo, None, None, None


def _extract_ref_gitlab(path_parts):
    """
    GitLab 支持子组，且 ref 段前一般有 '-'（新版）。
    返回 (project_path, ref, ref_type, path_in_repo)。
    project_path 是完整的 group[/subgroup]/repo。
    """
    # 找 "-" 分隔符
    if "-" in path_parts:
        dash_idx = path_parts.index("-")
        project_parts = path_parts[:dash_idx]
        rest = path_parts[dash_idx + 1:]
    else:
        # 老版：直接扫描 marker
        # 从后往前找第一个 marker，marker 之前视为 project path
        dash_idx = None
        for i, seg in enumerate(path_parts):
            if seg in ("tree", "blob", "commit", "commits", "tags", "raw"):
                dash_idx = i
                break
        if dash_idx is None or dash_idx < 2:
            # 找不到 marker，或 marker 出现太早（project path 至少 owner/repo 两段）
            return "/".join(path_parts), None, None, None
        project_parts = path_parts[:dash_idx]
        rest = path_parts[dash_idx:]

    project_path = "/".join(project_parts)
    if not rest:
        return project_path, None, None, None

    marker = rest[0]
    if marker in ("tree", "blob", "commits", "raw") and len(rest) >= 2:
        ref = rest[1]
        ref_type = "commit" if _is_commit_like(ref) else "ref"
        return project_path, ref, ref_type, _join_rest(rest[2:])

    if marker == "commit" and len(rest) >= 2:
        return project_path, rest[1], "commit", _join_rest(rest[2:])

    if marker == "tags" and len(rest) >= 2:
        return project_path, rest[1], "tag", _join_rest(rest[2:])

    return project_path, None, None, None


def _extract_ref_gitea(path_parts):
    """
    Gitea 形态：
      /<owner>/<repo>/src/branch/<ref>[/...]
      /<owner>/<repo>/src/tag/<ref>[/...]
      /<owner>/<repo>/src/commit/<sha>[/...]
      /<owner>/<repo>/commit/<sha>
      /<owner>/<repo>/raw/branch/<ref>/<path>
    """
    owner, repo = path_parts[0], path_parts[1]
    rest = path_parts[2:]

    if not rest:
        return owner, repo, None, None, None

    # /src/<kind>/<ref>[/...]  /raw/<kind>/<ref>[/...]
    if rest[0] in ("src", "raw") and len(rest) >= 3 and rest[1] in _GITEA_SRC_KIND:
        kind = rest[1]
        ref = rest[2]
        ref_type = {"branch": "ref", "tag": "tag", "commit": "commit"}[kind]
        return owner, repo, ref, ref_type, _join_rest(rest[3:])

    # /commit/<sha>
    if rest[0] == "commit" and len(rest) >= 2:
        return owner, repo, rest[1], "commit", _join_rest(rest[2:])

    return owner, repo, None, None, None


def parse_repository_url(repo_url: str, repo_type: str) -> Dict[str, Optional[str]]:
    """
    Parses a repository URL and returns its components.

    Backward-compatible: the returned dict keeps every field name and semantic
    the original implementation exposed (`base_url`, `owner`, `repo`,
    `project_path`, `server_url`). New fields are additive:

        - ref:            branch / tag name / commit sha extracted from the URL,
                          if present (e.g. ".../tree/2.0.0" -> "2.0.0").
                          None when the URL only points at the repo root.
        - ref_type:       one of "ref" (branch or tag, undetermined),
                          "tag", "commit". None when `ref` is None.
                          Note: distinguishing "branch" vs "tag" for a bare
                          `/tree/<name>` URL requires an API call; callers
                          may refine this later.
        - path_in_repo:   file path inside the repo, when URL is /blob/... etc.
        - canonical_url:  the repository-root URL (scheme + host + owner/repo),
                          suitable for storing in Project.repository_url so that
                          subsequent scans always start from a clean root.

    The function raises ValueError on invalid input, exactly like before.
    """
    if not repo_url:
        raise ValueError(f"{repo_type} 仓库 URL 不能为空")

    repo_url = repo_url.strip()
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{repo_type} 仓库 URL 必须使用 http 或 https 协议")

    # Split path segments, strip `.git` suffix on the *last non-empty* segment only.
    raw_path = parsed.path.strip("/")
    if not raw_path:
        raise ValueError(f"{repo_type} 仓库 URL 格式错误")

    path_parts = [p for p in raw_path.split("/") if p]
    if path_parts and path_parts[-1].endswith(".git"):
        path_parts[-1] = path_parts[-1][:-4]

    if len(path_parts) < 2:
        raise ValueError(f"{repo_type} 仓库 URL 格式错误")

    base = f"{parsed.scheme}://{parsed.netloc}"

    ref: Optional[str] = None
    ref_type: Optional[str] = None
    path_in_repo: Optional[str] = None

    if repo_type == "github":
        owner, repo, ref, ref_type, path_in_repo = _extract_ref_github(path_parts)
        if "github.com" in parsed.netloc:
            api_base = "https://api.github.com"
        else:
            # Enterprise GitHub
            api_base = f"{base}/api/v3"
        project_path = f"{owner}/{repo}"
        canonical_url = f"{base}/{owner}/{repo}"

    elif repo_type == "gitlab":
        project_path, ref, ref_type, path_in_repo = _extract_ref_gitlab(path_parts)
        project_parts = project_path.split("/") if project_path else []
        if len(project_parts) < 2:
            raise ValueError(f"{repo_type} 仓库 URL 格式错误")
        repo = project_parts[-1]
        owner = "/".join(project_parts[:-1])
        api_base = f"{base}/api/v4"
        canonical_url = f"{base}/{project_path}"

    elif repo_type == "gitea":
        owner, repo, ref, ref_type, path_in_repo = _extract_ref_gitea(path_parts)
        api_base = f"{base}/api/v1"
        project_path = f"{owner}/{repo}"
        canonical_url = f"{base}/{owner}/{repo}"

    else:
        raise ValueError(f"不支持的仓库类型: {repo_type}")

    return {
        "base_url": api_base,
        "owner": owner,
        "repo": repo,
        "project_path": project_path,
        "server_url": base,
        # 新增字段（附加式，历史调用者忽略即可）
        "ref": ref,
        "ref_type": ref_type,
        "path_in_repo": path_in_repo,
        "canonical_url": canonical_url,
    }


def extract_ref_from_url(repo_url: str, repo_type: str) -> Tuple[Optional[str], Optional[str]]:
    """
    便捷函数：只从 URL 里取 (ref, ref_type)。失败时返回 (None, None) 而非抛异常。
    供 API 层在建项目时快速判断"用户是否显式在 URL 里锚定了版本"。
    """
    try:
        info = parse_repository_url(repo_url, repo_type)
        return info.get("ref"), info.get("ref_type")
    except Exception:
        return None, None
