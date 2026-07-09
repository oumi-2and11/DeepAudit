"""
Evidence Chain (证据链) — deepaudit修改文档.md §5

选题原文要求："证据链需包含 文件位置 + 调用路径 + 验证结果"。
我们扩展为五段结构（贴近 §5.2 表述）：

  1. source_locations : List[SourceLocation]      文件+行+函数名+代码片段
  2. call_path        : List[CallEdge]            [{"from": "a:12:foo", "to": "b:34:bar"}, ...]
  3. taint_flow       : Optional[str]             "argv[1] -> parse::buf -> ... -> execve"
  4. verification     : VerificationEvidence      方法/命令/输出/退出码/判定
  5. references       : List[Reference]           CVE / CWE / commit

设计取舍：
- 不做 DB migration。整个证据链塞到现有 AgentFinding.finding_metadata JSON 列的
  "evidence_chain" 子键下，报告端直接读；这样 §5 独立于任何 alembic 变更就能落地。
- 不做 Pydantic 严格校验。Agent 输出的 JSON 天生脏，用 dict + 显式取字段 + 补 None
  比引入 BaseModel 更耐操。
- 不允许"占位式"完整。任何一段字段缺失/为空/长度不足，都要在 completeness 里显式
  标为缺项。这是选题里"证据链不完整必须打标"的直接实现。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# 完整度阈值：一段"存在"需要满足的最小样子
_MIN_SNIPPET_CHARS = 20          # 一段代码至少 20 字符才算 source_location 有效
_MIN_FLOW_ARROWS = 1             # taint_flow 里至少要有 1 个 "->"
_MIN_VERIF_TEXT_CHARS = 20       # verification.output/details 至少 20 字符


# ------------------------------------------------------------------
# 数据类
# ------------------------------------------------------------------

@dataclass
class SourceLocation:
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    function: str = ""
    code_snippet: str = ""

    def is_meaningful(self) -> bool:
        # 光有文件路径不算数——必须带代码片段（§5 验收指标）
        return bool(self.file) and len(self.code_snippet.strip()) >= _MIN_SNIPPET_CHARS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "function": self.function,
            "code_snippet": self.code_snippet,
        }


@dataclass
class CallEdge:
    frm: str = ""   # "handler.py:12:index"
    to: str = ""    # "utils.py:34:sanitize"

    def is_meaningful(self) -> bool:
        return bool(self.frm) and bool(self.to)

    def to_dict(self) -> Dict[str, Any]:
        return {"from": self.frm, "to": self.to}


@dataclass
class VerificationEvidence:
    method: str = ""        # "c_test (project 模式, ASAN)"
    command: str = ""       # 实际执行的命令
    output: str = ""        # 关键输出片段（ASAN 报告 / stdout 命中）
    exit_code: Optional[int] = None
    verdict: str = ""       # confirmed / likely / uncertain / false_positive
    tool_name: str = ""     # run_code / c_test / sandbox_exec ...

    def is_meaningful(self) -> bool:
        # "方法 + (命令 or 输出)" 才算有实质证据；只写一句 verdict 不算
        if not self.method:
            return False
        body_len = len((self.output or "") + (self.command or ""))
        return body_len >= _MIN_VERIF_TEXT_CHARS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "command": self.command,
            "output": self.output,
            "exit_code": self.exit_code,
            "verdict": self.verdict,
            "tool_name": self.tool_name,
        }


@dataclass
class Reference:
    kind: str = ""    # "CWE" / "CVE" / "commit"
    value: str = ""   # "CWE-78" / "CVE-2024-1234" / "abc123"
    url: str = ""

    def is_meaningful(self) -> bool:
        return bool(self.value)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "url": self.url}


@dataclass
class EvidenceChain:
    source_locations: List[SourceLocation] = field(default_factory=list)
    call_path: List[CallEdge] = field(default_factory=list)
    taint_flow: str = ""
    verification: VerificationEvidence = field(default_factory=VerificationEvidence)
    references: List[Reference] = field(default_factory=list)

    # --- 完整度 ---

    def completeness(self) -> Dict[str, bool]:
        """返回 5 段每一段是否达标。"""
        return {
            "source_locations": any(s.is_meaningful() for s in self.source_locations),
            "call_path": any(e.is_meaningful() for e in self.call_path),
            "taint_flow": self.taint_flow.count("->") >= _MIN_FLOW_ARROWS,
            "verification": self.verification.is_meaningful(),
            "references": any(r.is_meaningful() for r in self.references),
        }

    def completeness_score(self) -> str:
        """'3/5' 这种展示串。"""
        c = self.completeness()
        got = sum(1 for v in c.values() if v)
        return f"{got}/{len(c)}"

    def missing_sections(self) -> List[str]:
        c = self.completeness()
        return [k for k, v in c.items() if not v]

    # --- 序列化 ---

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_locations": [s.to_dict() for s in self.source_locations],
            "call_path": [e.to_dict() for e in self.call_path],
            "taint_flow": self.taint_flow,
            "verification": self.verification.to_dict(),
            "references": [r.to_dict() for r in self.references],
            "completeness": self.completeness(),
            "completeness_score": self.completeness_score(),
        }

    # --- 从 raw finding 构造 ---

    @classmethod
    def from_finding(cls, finding: Dict[str, Any]) -> "EvidenceChain":
        """
        把一个 finding dict 里散落各处的证据字段收拢到 EvidenceChain。

        兼容 Analysis / Refinement / Verification 三个来源都可能贡献的字段。
        看不到的段留空，由 completeness() 显式暴露缺项——不允许"胡诌一段"。
        """
        # 1) source_locations
        source_locations: List[SourceLocation] = []
        file_path = str(finding.get("file_path") or "").strip()
        code_snippet = str(finding.get("code_snippet") or "").strip()
        if file_path or code_snippet:
            line_start = _safe_int(
                finding.get("line_start") or finding.get("line") or 0
            )
            line_end = _safe_int(
                finding.get("line_end") or (line_start if line_start else 0)
            )
            source_locations.append(SourceLocation(
                file=file_path,
                line_start=line_start,
                line_end=line_end,
                function=str(finding.get("function_name") or finding.get("function") or ""),
                code_snippet=code_snippet,
            ))

        # 2) call_path —— 允许两种输入形式：
        #    - finding["call_path"] = [{"from": "...", "to": "..."}]
        #    - finding["call_path"] = "main -> parse -> foo -> system"（一串箭头）
        call_path: List[CallEdge] = []
        raw_call = finding.get("call_path")
        if isinstance(raw_call, list):
            for edge in raw_call:
                if isinstance(edge, dict):
                    call_path.append(CallEdge(
                        frm=str(edge.get("from") or edge.get("frm") or ""),
                        to=str(edge.get("to") or ""),
                    ))
                elif isinstance(edge, str) and "->" in edge:
                    a, _, b = edge.partition("->")
                    call_path.append(CallEdge(frm=a.strip(), to=b.strip()))
        elif isinstance(raw_call, str) and "->" in raw_call:
            nodes = [n.strip() for n in raw_call.split("->") if n.strip()]
            for i in range(len(nodes) - 1):
                call_path.append(CallEdge(frm=nodes[i], to=nodes[i + 1]))

        # 3) taint_flow —— Refinement / Analysis 都会填 data_flow
        taint_flow = str(
            finding.get("taint_flow")
            or finding.get("data_flow")
            or ""
        ).strip()

        # 4) verification —— Verification Agent 的核心产物
        ve = _extract_verification(finding)

        # 5) references —— CWE + CVE + commit
        references: List[Reference] = []
        for kind_key, ref_kind in (("cwe_id", "CWE"), ("cwe", "CWE"), ("cve_id", "CVE"), ("cve", "CVE")):
            v = finding.get(kind_key)
            if v:
                references.append(Reference(kind=ref_kind, value=str(v)))
        raw_refs = finding.get("references")
        if isinstance(raw_refs, list):
            for r in raw_refs:
                if isinstance(r, dict):
                    kind = str(r.get("kind") or ("CWE" if "cwe" in r else "CVE" if "cve" in r else "")).upper()
                    value = str(r.get("value") or r.get("cwe") or r.get("cve") or r.get("id") or "")
                    if value:
                        references.append(Reference(kind=kind, value=value, url=str(r.get("url") or "")))
                elif isinstance(r, str) and r.strip():
                    references.append(Reference(kind="", value=r.strip()))

        return cls(
            source_locations=source_locations,
            call_path=call_path,
            taint_flow=taint_flow,
            verification=ve,
            references=references,
        )

    # --- Markdown 渲染（§5.2 模板） ---

    def to_markdown(self, indent_level: int = 0) -> str:
        """
        产出 §5.2 的 5 小节 markdown 面板。传 indent_level=1 时把 `###` 降级为 `####`。
        """
        h = "#" * (3 + indent_level)  # ### 或 ####
        sub_h = "#" * (4 + indent_level)  # ####
        c = self.completeness()
        got = sum(1 for v in c.values() if v)
        missing = [k for k, v in c.items() if not v]

        lines: List[str] = []
        # 头：完整度徽章
        if got == len(c):
            lines.append(f"**证据链完整度**：{got}/{len(c)} ✔️ (完整)")
        else:
            lines.append(
                f"**证据链完整度**：{got}/{len(c)} ⚠️ 证据不完整 "
                f"(缺少：{', '.join(missing)})"
            )
        lines.append("")

        # 1) 源位置
        lines.append(f"{sub_h} 1) 源位置")
        if not self.source_locations:
            lines.append("_未提供_")
        else:
            for s in self.source_locations:
                head = f"- `{s.file}`"
                if s.line_start:
                    head += f":{s.line_start}"
                    if s.line_end and s.line_end != s.line_start:
                        head += f"-{s.line_end}"
                if s.function:
                    head += f"  (函数 `{s.function}`)"
                lines.append(head)
                if s.code_snippet:
                    # 保留原样代码块
                    lang = _guess_lang(s.file)
                    lines.append(f"```{lang}")
                    # 截断过长代码
                    snippet = s.code_snippet
                    if len(snippet) > 2000:
                        snippet = snippet[:2000] + "\n... (已截断)"
                    lines.append(snippet)
                    lines.append("```")
        lines.append("")

        # 2) 调用路径
        lines.append(f"{sub_h} 2) 调用路径")
        if not self.call_path:
            lines.append("_未提供_")
        else:
            chain = " → ".join(
                # 首个节点用 from，后面拼 to
                [self.call_path[0].frm] + [e.to for e in self.call_path]
            )
            lines.append(f"`{chain}` ({len(self.call_path)} 跳)")
        lines.append("")

        # 3) 污点流
        lines.append(f"{sub_h} 3) 污点流")
        if self.taint_flow:
            lines.append(f"`{self.taint_flow}`")
        else:
            lines.append("_未提供_")
        lines.append("")

        # 4) 验证
        lines.append(f"{sub_h} 4) 验证")
        if not self.verification.is_meaningful() and not self.verification.method:
            lines.append("_未验证 / 未提供验证证据_")
        else:
            v = self.verification
            if v.method:
                lines.append(f"- **方法:** {v.method}")
            if v.tool_name:
                lines.append(f"- **工具:** `{v.tool_name}`")
            if v.command:
                lines.append("- **命令:**")
                lines.append("  ```")
                cmd = v.command
                if len(cmd) > 500:
                    cmd = cmd[:500] + "... (已截断)"
                lines.append(f"  {cmd}")
                lines.append("  ```")
            if v.output:
                lines.append("- **关键输出:**")
                lines.append("  ```")
                out = v.output
                if len(out) > 1500:
                    out = out[:1500] + "\n  ... (已截断)"
                lines.append(f"  {out}")
                lines.append("  ```")
            if v.exit_code is not None:
                lines.append(f"- **退出码:** `{v.exit_code}`")
            if v.verdict:
                lines.append(f"- **判定:** **{v.verdict}**")
        lines.append("")

        # 5) 参考
        lines.append(f"{sub_h} 5) 参考")
        if not self.references:
            lines.append("_未提供_")
        else:
            for r in self.references:
                label = f"{r.kind}: `{r.value}`" if r.kind else f"`{r.value}`"
                if r.url:
                    label += f" — {r.url}"
                lines.append(f"- {label}")
        lines.append("")

        return "\n".join(lines)


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _safe_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _guess_lang(file_path: str) -> str:
    if not file_path:
        return ""
    p = file_path.lower()
    for ext, lang in (
        (".c", "c"), (".h", "c"),
        (".cpp", "cpp"), (".cc", "cpp"), (".cxx", "cpp"), (".hpp", "cpp"),
        (".py", "python"),
        (".js", "javascript"), (".ts", "typescript"),
        (".java", "java"),
        (".go", "go"),
        (".rb", "ruby"),
        (".php", "php"),
        (".sh", "bash"), (".bash", "bash"),
        (".rs", "rust"),
    ):
        if p.endswith(ext):
            return lang
    return ""


def _extract_verification(finding: Dict[str, Any]) -> VerificationEvidence:
    """
    从 finding 各种可能的字段名里拼出 VerificationEvidence。

    兼容：
      - Verification Agent 输出的 verification_method / verification_details / verdict
      - PoC 字段（poc.payload / poc.steps）
      - finding_metadata.verification / .refinement
    """
    method = str(finding.get("verification_method") or "").strip()
    details = finding.get("verification_details") or ""
    if isinstance(details, dict):
        # 有时 Agent 返回结构化 details
        details_str = "\n".join(
            f"{k}: {v}" for k, v in details.items()
            if isinstance(v, (str, int, float))
        )
    else:
        details_str = str(details or "")

    verification_result = finding.get("verification_result")
    if isinstance(verification_result, dict):
        vr_details = verification_result.get("details") or verification_result.get("output") or ""
        if vr_details and not details_str:
            details_str = str(vr_details)

    # 从 poc 里拿 command / harness_code 作为"命令"
    command = ""
    poc = finding.get("poc")
    if isinstance(poc, dict):
        command = str(poc.get("payload") or poc.get("command") or poc.get("harness_code") or "")

    verdict = str(finding.get("verdict") or "").strip()
    if not verdict:
        # 从 is_verified 反推
        if finding.get("is_verified"):
            verdict = "confirmed"

    tool_name = ""
    # metadata 里可能带工具名
    meta = finding.get("finding_metadata") or {}
    if isinstance(meta, dict):
        v_meta = meta.get("verification") or {}
        if isinstance(v_meta, dict):
            tool_name = str(v_meta.get("tool_name") or "")
            if not method:
                method = str(v_meta.get("method") or "")
            if not command:
                command = str(v_meta.get("command") or "")
            if not details_str:
                details_str = str(v_meta.get("output") or "")

    exit_code = None
    if isinstance(meta, dict):
        ec = (meta.get("verification") or {}).get("exit_code") if isinstance(meta.get("verification"), dict) else None
        if ec is not None:
            try:
                exit_code = int(ec)
            except (TypeError, ValueError):
                exit_code = None

    return VerificationEvidence(
        method=method,
        command=command,
        output=details_str,
        exit_code=exit_code,
        verdict=verdict,
        tool_name=tool_name,
    )
