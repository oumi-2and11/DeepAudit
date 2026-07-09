"""
Refinement Agent (二次分析层) - deepaudit修改文档.md §4

针对 Analysis Agent 产出的**低置信度 finding**（一句话描述、无代码片段、无数据流），
在送 Verification 之前做一次**确定性预取 + 定向 LLM 判决**，把 Recon 那种
「src/xx.c:1690 - argv_parse_cmd 执行 route_script」类的模糊描述升格为可验证的
Finding，或者干脆判为 false_positive 丢掉。

分桶策略（阈值可配）：
  confidence ≥ 0.8         → 直接 passthrough 给 Verification（不精修）
  0.5 ≤ confidence < 0.8   → 走 Refinement 精修流程
  confidence < 0.5         → 丢弃（记录到 dropped_findings，报告里进"扫描但过滤"栏目）

精修流程（每条 finding 独立执行，串行）：
  1. 确定性预取：read_file(file, [l-30, l+30]) —— 让 finding 拥有真实的 code_snippet
  2. 可选辅助：如果能从描述里提取到 sink 关键词，跑一次 search_code 找调用者
  3. 一次性 LLM 判决（不是全套 ReAct，就 chat 一次）：
        输出 {"verdict": "confirmed"|"false_positive"|"still_unclear",
              "code_snippet": "...", "data_flow": "...", "why": "...",
              "new_confidence": 0.xx, "suggested_verification": "..."}
  4. 归并：
        confirmed       → refined_findings（升级 confidence + 填 code_snippet/data_flow）
        false_positive  → dropped_findings（附 why）
        still_unclear   → unclear_findings（进报告独立分区）

设计取舍：
- 不做 ReAct 循环。Refinement 的目标就是让 LLM 看一眼真实代码然后判个刑，多轮反而
  容易发散、堆 token。整轮下来每条 finding 只花 1 次 LLM call。
- 不允许 LLM 决定要不要读文件。它拿到的 prompt 里已经带上确定性抓好的 30 行上下文，
  避免它偷懒直接说 "无法确定" 就摆烂。
- Refinement 不生成新 finding，只调整/丢弃/放行现有 finding。
"""

import asyncio
import json
import logging
import os
import re
from typing import List, Dict, Any, Optional, Tuple

from .base import BaseAgent, AgentConfig, AgentResult, AgentType, AgentPattern, TaskHandoff
from ..json_parser import AgentJsonParser

logger = logging.getLogger(__name__)


REFINEMENT_SYSTEM_PROMPT = """你是 DeepAudit 的复审 Agent（Refinement），一个**严格的**安全审计裁判。

## 你的角色
Analysis Agent 已经给出了一批**低置信度**发现（60% 左右），描述通常只有一句话，
既没有真实代码片段也没有数据流。你的任务是对每一条这样的发现**独立做出判决**：

  - **confirmed**：读了真实代码后，你确信这就是一个可验证的漏洞（升格进 Verification）
  - **false_positive**：读了真实代码后，你确信这不是漏洞（丢弃，附理由）
  - **still_unclear**：读了代码但缺关键上下文（例如 sink 定义、taint source 未知），
    保留但降级到"待人工确认"分区

## 严格约束
1. **只能基于 prompt 里给你的真实代码**下判断，禁止凭空猜测项目里"应该有"或"可能有"什么。
2. **不接受"无法构造 PoC"作为借口**。如果代码里确实有威胁（例如 openvpn_execve 拼接了用户可控字符串），
   即便你不会写 PoC，也要判 confirmed 并给出触发路径。
3. **new_confidence 必须与 verdict 一致**：
   - confirmed → new_confidence ≥ 0.75
   - false_positive → new_confidence ≤ 0.3
   - still_unclear → 0.3 < new_confidence < 0.75

## 输出格式（严格 JSON，禁止 Markdown 包裹）

```json
{
    "verdict": "confirmed | false_positive | still_unclear",
    "new_confidence": 0.85,
    "code_snippet": "从提供的代码上下文中摘出真正体现漏洞的 5~30 行代码",
    "data_flow": "user_input -> parse_argv() -> route_script_path -> execve()",
    "call_path": ["main -> parse_argv", "parse_argv -> route_script", "route_script -> execve"],
    "cwe_id": "CWE-78",
    "why": "解释判决理由，引用你在代码中看到的具体行",
    "suggested_verification": "建议 Verification Agent 用什么工具/PoC 思路验证（若 verdict=confirmed）"
}
```

**只输出 JSON，不要有 Thought / Action / Markdown 代码块外壳的额外文字。**
"""


class RefinementAgent(BaseAgent):
    """
    低置信度发现二次分析 Agent。

    与 Recon/Analysis/Verification 不同，Refinement 不跑 ReAct 循环：
    一条 finding = 一次 LLM 判决。这是因为它的输入已经**由代码而非模型意愿**
    提供了完整上下文（我们预先读好了文件、跑好了 search_code），LLM 只需要
    做最后的分类。
    """

    # 分桶阈值
    HIGH_CONF_THRESHOLD = 0.8   # ≥ 此值直接 passthrough
    LOW_CONF_THRESHOLD = 0.5    # < 此值直接丢弃

    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        config = AgentConfig(
            name="Refinement",
            agent_type=AgentType.ANALYSIS,  # 归到 Analysis 家族，让树/事件视觉一致
            pattern=AgentPattern.PLAN_AND_EXECUTE,
            max_iterations=1,  # 每条 finding 一次 LLM，不需要迭代
            system_prompt=REFINEMENT_SYSTEM_PROMPT,
        )
        super().__init__(config, llm_service, tools, event_emitter)

        # 统计
        self._refined: List[Dict[str, Any]] = []      # verdict=confirmed 的
        self._dropped: List[Dict[str, Any]] = []      # verdict=false_positive 或 confidence<0.5 直接丢的
        self._unclear: List[Dict[str, Any]] = []      # verdict=still_unclear 的
        self._passthrough: List[Dict[str, Any]] = []  # confidence ≥ 0.8 直接放行的

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        import time
        start_time = time.time()

        # 兼容不同来源：既支持从 handoff 拿，也支持从 previous_results 或直接 findings 拿
        findings: List[Dict[str, Any]] = []
        handoff_data = input_data.get("handoff")
        if handoff_data:
            if isinstance(handoff_data, dict):
                findings = handoff_data.get("key_findings", []) or []
            elif isinstance(handoff_data, TaskHandoff):
                findings = handoff_data.key_findings or []

        if not findings:
            prev = input_data.get("previous_results") or {}
            analysis = prev.get("analysis") or {}
            if isinstance(analysis, dict) and "data" in analysis:
                analysis = analysis["data"]
            findings = (analysis or {}).get("findings", []) if isinstance(analysis, dict) else []

        if not findings:
            # Orchestrator 直接把整套 findings 塞在 previous_results.findings 里
            findings = (input_data.get("previous_results") or {}).get("findings", []) or []

        # 去掉非 dict
        findings = [f for f in findings if isinstance(f, dict)]

        project_root = input_data.get("project_root") or "."

        await self.emit_thinking(
            f"🧪 Refinement Agent 启动，收到 {len(findings)} 个待复审 finding"
        )

        # === 分桶 ===
        high, mid, low = self._bucketize(findings)
        self._passthrough = list(high)
        for f in low:
            # 低置信度直接丢，但记录原因
            drop = dict(f)
            drop["_refinement"] = {
                "verdict": "auto_dropped_low_confidence",
                "reason": f"原始 confidence={f.get('confidence', 0)} < {self.LOW_CONF_THRESHOLD}，未进入 Refinement",
            }
            self._dropped.append(drop)

        await self.emit_event(
            "info",
            f"📊 分桶: 直接放行 {len(high)} | 精修 {len(mid)} | 直接丢弃 {len(low)}",
        )

        # === 精修中桶 ===
        # 为避免长时间阻塞，串行处理并支持取消
        for idx, finding in enumerate(mid, 1):
            if self.is_cancelled:
                logger.info(f"[{self.name}] Cancelled during refinement loop")
                break

            try:
                verdict_data = await self._refine_one(finding, project_root, idx, len(mid))
            except Exception as e:
                logger.error(f"[{self.name}] refine_one crashed for {finding.get('title')}: {e}", exc_info=True)
                # 崩了当 unclear 处理，不静默丢
                verdict_data = {
                    "verdict": "still_unclear",
                    "new_confidence": finding.get("confidence", 0.6),
                    "code_snippet": finding.get("code_snippet", ""),
                    "data_flow": "",
                    "why": f"Refinement 内部错误: {e}",
                    "suggested_verification": "",
                }

            merged = self._merge_verdict(finding, verdict_data)
            v = verdict_data.get("verdict", "still_unclear")
            if v == "confirmed":
                self._refined.append(merged)
            elif v == "false_positive":
                self._dropped.append(merged)
            else:
                self._unclear.append(merged)

        duration_ms = int((time.time() - start_time) * 1000)

        # 交给 Verification 的 findings = passthrough(高置信) + refined(confirmed)
        # unclear 不进 Verification，它们直接进报告的"待人工确认"分区
        outbound = self._passthrough + self._refined

        summary = (
            f"Refinement 完成: passthrough={len(self._passthrough)}, "
            f"refined_confirmed={len(self._refined)}, "
            f"dropped={len(self._dropped)}, "
            f"unclear={len(self._unclear)}"
        )
        await self.emit_event("info", summary)

        # handoff 给 Verification
        handoff = self.create_handoff(
            to_agent="verification",
            summary=summary,
            key_findings=outbound[:20],
            suggested_actions=[
                {
                    "action": "verify",
                    "target": f.get("file_path", ""),
                    "vulnerability_type": f.get("vulnerability_type", "unknown"),
                    "priority": "high",
                }
                for f in outbound[:15]
            ],
            attention_points=[f"未确认发现 {len(self._unclear)} 条已归入待人工确认分区，不进 Verification"] if self._unclear else [],
            context_data={
                "refinement_stats": {
                    "passthrough": len(self._passthrough),
                    "confirmed": len(self._refined),
                    "dropped": len(self._dropped),
                    "unclear": len(self._unclear),
                }
            },
        )

        return AgentResult(
            success=True,
            data={
                # 关键：给 Orchestrator 的下游一份"精修后应该继续走 Verification 的清单"
                "findings": outbound,
                # 报告端消费的两个新分区
                "dropped_findings": self._dropped,
                "unclear_findings": self._unclear,
                # 也把 passthrough / refined 分开留一份，方便追踪
                "refinement_details": {
                    "passthrough": self._passthrough,
                    "refined_confirmed": self._refined,
                },
                "summary": summary,
            },
            iterations=1,
            tool_calls=self._tool_calls,
            tokens_used=self._total_tokens,
            duration_ms=duration_ms,
            handoff=handoff,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _bucketize(
        self,
        findings: List[Dict[str, Any]],
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        high, mid, low = [], [], []
        for f in findings:
            # SCA / Preflight 已确认的直接进 high 桶不精修
            src = (f.get("finding_metadata") or {}).get("source") or f.get("source")
            if src in ("sca", "secrets") or f.get("is_verified"):
                high.append(f)
                continue

            conf = f.get("confidence")
            try:
                conf = float(conf) if conf is not None else 0.6
            except (TypeError, ValueError):
                conf = 0.6

            if conf >= self.HIGH_CONF_THRESHOLD:
                high.append(f)
            elif conf >= self.LOW_CONF_THRESHOLD:
                mid.append(f)
            else:
                low.append(f)
        return high, mid, low

    async def _refine_one(
        self,
        finding: Dict[str, Any],
        project_root: str,
        idx: int,
        total: int,
    ) -> Dict[str, Any]:
        """对单条 finding 做一次精修判决。返回 LLM 输出的 verdict dict。"""
        title = finding.get("title", "Unknown")
        file_path = finding.get("file_path", "") or ""
        line = finding.get("line_start") or finding.get("line") or 0

        await self.emit_thinking(
            f"🔎 [{idx}/{total}] 精修: {title[:60]} ({file_path}:{line})"
        )

        # === 步骤 1: 确定性预取代码片段 ===
        code_context = await self._deterministic_read(file_path, line)

        # === 步骤 2: 可选辅助 search_code（找 sink 调用者） ===
        sink_hint = self._extract_sink_hint(finding)
        search_context = ""
        if sink_hint:
            search_context = await self._deterministic_search(sink_hint)

        # === 步骤 3: 一次性 LLM 判决 ===
        user_prompt = self._build_refinement_prompt(
            finding=finding,
            code_context=code_context,
            search_context=search_context,
            sink_hint=sink_hint,
        )

        messages = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        # 精修不需要流式思考事件那么细，但我们还是用 stream_llm_call 保持一致
        try:
            llm_output, tokens = await self.stream_llm_call(messages)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"[{self.name}] LLM call failed: {e}", exc_info=True)
            return {
                "verdict": "still_unclear",
                "new_confidence": finding.get("confidence", 0.6),
                "code_snippet": code_context[:1500] if code_context else "",
                "data_flow": "",
                "why": f"LLM 判决失败: {e}",
                "suggested_verification": "",
            }

        self._total_tokens += tokens

        return self._parse_verdict(llm_output, fallback_snippet=code_context)

    async def _deterministic_read(self, file_path: str, line: int) -> str:
        """
        用 read_file 工具确定性地把 [line-30, line+30] 的代码抓出来。

        LLM 不参与决定读不读、读哪段——由代码控制。
        """
        if not file_path:
            return ""

        # 清理可能的行号后缀 file.c:1690
        clean_path = file_path.split(":")[0] if ":" in file_path else file_path

        # 尝试多种起始行：如果 line=0（没有行号），就读文件前 200 行
        if line and line > 0:
            start = max(1, int(line) - 30)
            end = int(line) + 30
        else:
            start, end = 1, 200

        tool = self.tools.get("read_file")
        if not tool:
            return ""

        try:
            self._tool_calls += 1
            result = await tool.execute(file_path=clean_path, start_line=start, end_line=end)
            if not result or not getattr(result, "success", False):
                # 兼容 read_file 只返回字符串的老实现
                if isinstance(result, str):
                    return result[:4000]
                err = getattr(result, "error", None)
                return f"[read_file failed: {err or 'unknown'}]"
            data = getattr(result, "data", "")
            return str(data)[:4000] if data else ""
        except Exception as e:
            logger.warning(f"[{self.name}] deterministic_read failed: {e}")
            return f"[read_file exception: {e}]"

    async def _deterministic_search(self, sink_hint: str) -> str:
        """对已经推断出来的 sink 名字跑一次 search_code，取头几行。"""
        tool = self.tools.get("search_code")
        if not tool or not sink_hint:
            return ""

        try:
            self._tool_calls += 1
            result = await tool.execute(keyword=sink_hint, max_results=8)
            if result and getattr(result, "success", False):
                return str(getattr(result, "data", ""))[:1500]
        except Exception as e:
            logger.debug(f"[{self.name}] deterministic_search failed: {e}")
        return ""

    def _extract_sink_hint(self, finding: Dict[str, Any]) -> str:
        """从 finding 的描述里粗略提取一个可搜索的 sink 名字。"""
        candidates = [
            finding.get("sink"),
            finding.get("vulnerability_type"),
        ]
        for c in candidates:
            if c and isinstance(c, str) and len(c) > 2 and " " not in c:
                return c

        desc = (finding.get("description", "") or "") + " " + (finding.get("title", "") or "")
        # 抓 xxx() 形式的函数名
        m = re.search(r"([A-Za-z_][A-Za-z0-9_]{3,})\s*\(", desc)
        if m:
            return m.group(1)
        return ""

    def _build_refinement_prompt(
        self,
        finding: Dict[str, Any],
        code_context: str,
        search_context: str,
        sink_hint: str,
    ) -> str:
        return f"""请对下面这条**低置信度发现**做出判决。

## 原始发现 (来自 Analysis Agent)

- 标题: {finding.get('title', 'N/A')}
- 类型: {finding.get('vulnerability_type', 'unknown')}
- 严重度: {finding.get('severity', 'medium')}
- 原始置信度: {finding.get('confidence', 0.6)}
- 文件位置: {finding.get('file_path', 'N/A')}:{finding.get('line_start') or finding.get('line', 0)}
- 描述: {finding.get('description', '(空)') or '(空)'}
- 已有的 code_snippet: {finding.get('code_snippet') or '(无)'}

## 已经为你抓取好的**真实代码上下文** (由 read_file 工具确定性获取)

```
{code_context or '(未能读取到代码，可能是文件不存在或路径错误)'}
```

## Sink 函数的相关调用点 (如果检测到)
sink 关键词: {sink_hint or '(未提取到)'}

```
{search_context or '(无)'}
```

## 你的任务
基于上述**真实代码**（而不是原始描述），判断这条发现是不是真实漏洞。

严格按照以下 JSON 格式输出，不要加任何 Markdown、Thought、Action：

{{
    "verdict": "confirmed | false_positive | still_unclear",
    "new_confidence": 0.xx,
    "code_snippet": "从上面真实代码中摘出体现漏洞的 5~30 行",
    "data_flow": "user_input -> ... -> sink",
    "call_path": ["main -> parse_argv", "parse_argv -> ...", "... -> sink"],
    "cwe_id": "CWE-xx",
    "why": "为什么这么判，引用你在代码里看到的行号或函数名",
    "suggested_verification": "如果 confirmed，建议 Verification Agent 用什么工具/PoC 思路验证"
}}
"""

    def _parse_verdict(self, llm_output: str, fallback_snippet: str = "") -> Dict[str, Any]:
        """把 LLM 输出解析为 verdict dict，失败时退化到 still_unclear。"""
        text = (llm_output or "").strip()

        # 去掉可能的 markdown 代码块外壳
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

        parsed = AgentJsonParser.parse(text, default={})
        if not isinstance(parsed, dict) or not parsed:
            return {
                "verdict": "still_unclear",
                "new_confidence": 0.55,
                "code_snippet": fallback_snippet[:1500] if fallback_snippet else "",
                "data_flow": "",
                "why": f"LLM 输出无法解析: {text[:200]}",
                "suggested_verification": "",
            }

        verdict = parsed.get("verdict", "still_unclear")
        if verdict not in ("confirmed", "false_positive", "still_unclear"):
            verdict = "still_unclear"

        try:
            new_conf = float(parsed.get("new_confidence", 0.55))
        except (TypeError, ValueError):
            new_conf = 0.55

        # 强制 verdict 与 new_confidence 一致（防止 LLM 自己打自己嘴）
        if verdict == "confirmed" and new_conf < 0.75:
            new_conf = 0.8
        elif verdict == "false_positive" and new_conf > 0.3:
            new_conf = 0.2
        elif verdict == "still_unclear":
            new_conf = max(0.35, min(0.7, new_conf))

        return {
            "verdict": verdict,
            "new_confidence": new_conf,
            "code_snippet": parsed.get("code_snippet") or fallback_snippet[:1500] or "",
            "data_flow": parsed.get("data_flow") or "",
            "call_path": parsed.get("call_path") or [],
            "cwe_id": parsed.get("cwe_id") or "",
            "why": parsed.get("why") or "",
            "suggested_verification": parsed.get("suggested_verification") or "",
        }

    def _merge_verdict(
        self,
        finding: Dict[str, Any],
        verdict_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """把 verdict 结果并回原 finding。保留 metadata 里的 refinement 痕迹。"""
        merged = dict(finding)
        merged["confidence"] = verdict_data.get("new_confidence", finding.get("confidence", 0.6))
        # 只有当 LLM 给出了非空 code_snippet 时才覆盖，防止把原 snippet 清空
        if verdict_data.get("code_snippet"):
            merged["code_snippet"] = verdict_data["code_snippet"]
        if verdict_data.get("data_flow"):
            merged["data_flow"] = verdict_data["data_flow"]
        if verdict_data.get("call_path"):
            merged["call_path"] = verdict_data["call_path"]
        if verdict_data.get("cwe_id") and not merged.get("cwe_id") and not merged.get("cwe"):
            merged["cwe_id"] = verdict_data["cwe_id"]
        if verdict_data.get("suggested_verification"):
            merged["suggested_verification"] = verdict_data["suggested_verification"]

        meta = dict(merged.get("finding_metadata") or {})
        meta["refinement"] = {
            "verdict": verdict_data.get("verdict"),
            "new_confidence": verdict_data.get("new_confidence"),
            "why": verdict_data.get("why", "")[:1000],
        }
        merged["finding_metadata"] = meta
        return merged
