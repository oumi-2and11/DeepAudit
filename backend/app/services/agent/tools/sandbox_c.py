"""
C / C++ 语言动态验证工具链

对标 §3 修改方案：
- CTestTool  : gcc / clang 编译 + 运行 (可开 AddressSanitizer)
- CppTestTool: g++ / clang++ 编译 + 运行
- FuzzTestTool: clang -fsanitize=fuzzer,address 短时 fuzz (libFuzzer)

设计要点：
1. 代码通过 base64 传入容器再解码写盘，避免 shell 转义地狱
2. 两种运行模式:
    - snippet : 单文件 PoC / harness
    - project : 需要 configure+make 的完整项目 (挂载 host_workdir 到 /workspace 只读)
3. 输出解析 ASAN / UBSAN / SEGV / LeakSanitizer / stack-buffer-overflow 等特征
4. 对内存类漏洞天然给出证据 (ASAN 报告 = 有力证据链)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shlex
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult
from .sandbox_language import BaseLanguageTestTool, LanguageTestInput
from .sandbox_tool import SandboxManager

logger = logging.getLogger(__name__)


# ============================================================
# 输入 Schema
# ============================================================

class CTestInput(LanguageTestInput):
    """C/C++ 测试输入"""

    mode: str = Field(
        default="snippet",
        description="运行模式: snippet (单文件 PoC) | project (整个项目 configure+make)",
    )
    entry: Optional[str] = Field(
        default=None,
        description="project 模式下的入口命令，例如 'make check' 或 './poc-driver'",
    )
    build_cmd: Optional[str] = Field(
        default=None,
        description="project 模式下的构建命令，例如 './configure && make' (默认 'make')",
    )
    extra_flags: Optional[str] = Field(
        default=None,
        description="额外编译参数，例如 '-lm -lssl'",
    )
    sanitizer: str = Field(
        default="address",
        description="使用的 sanitizer: address | undefined | address,undefined | none",
    )
    argv: Optional[List[str]] = Field(
        default=None,
        description="传给可执行文件的 argv (list)",
    )
    stdin: Optional[str] = Field(
        default=None,
        description="传给可执行文件的 stdin 内容",
    )
    function_signature: Optional[str] = Field(
        default=None,
        description="漏洞函数原型 (snippet 模式下用于自动生成 main wrapper)",
    )


# ============================================================
# 基类
# ============================================================

class BaseCTestTool(BaseLanguageTestTool):
    """C / C++ 测试基类

    与其它语言工具一样最终走 sandbox_manager.execute_command，
    但 execute_command 挂载的是临时空目录 (rw)，不会拉到项目源码；
    因此 project 模式需要额外走 execute_tool_command 挂载 host_workdir。
    """

    COMPILER = "gcc"           # 子类覆盖: gcc / g++
    STD_FLAG = "-std=c11"      # 子类覆盖
    FILE_EXTENSION = ".c"
    LANGUAGE_NAME = "C"

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        project_root: str = ".",
    ):
        super().__init__(sandbox_manager=sandbox_manager, project_root=project_root)

    # ---------- BaseLanguageTestTool 兼容位 (未直接使用) ----------

    def _build_wrapper_code(
        self,
        code: str,
        params: Optional[Dict[str, str]],
        function_signature: Optional[str] = None,
        **_: Any,
    ) -> str:
        """如果 code 里已经有 main() 就原样返回，否则包一个 main() 调用 vuln()."""
        if re.search(r"\bint\s+main\s*\(", code):
            return code

        if function_signature:
            # 用户明确给了 vuln 原型，生成一个通用调用者
            wrapper = self._make_wrapper_from_signature(code, function_signature, params)
            if wrapper:
                return wrapper

        # 兜底：直接塞进 main
        return (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "int main(int argc, char **argv) {\n"
            + code
            + "\n    return 0;\n}\n"
        )

    def _build_command(self, code: str) -> str:  # noqa: D401 - Base 兼容
        """本工具不使用父类的 _build_command 路径 (由 _execute 直接构造)。"""
        raise NotImplementedError("BaseCTestTool 使用自定义 _execute 流程")

    # ---------- 主入口 ----------

    async def _execute(
        self,
        code: Optional[str] = None,
        file_path: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        timeout: int = 60,
        mode: str = "snippet",
        entry: Optional[str] = None,
        build_cmd: Optional[str] = None,
        extra_flags: Optional[str] = None,
        sanitizer: str = "address",
        argv: Optional[List[str]] = None,
        stdin: Optional[str] = None,
        function_signature: Optional[str] = None,
        **kwargs,
    ) -> ToolResult:
        try:
            await self.sandbox_manager.initialize()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Sandbox init failed: {e}")

        if not self.sandbox_manager.is_available:
            return ToolResult(success=False, error="沙箱环境不可用 (Docker Unavailable)")

        mode = (mode or "snippet").lower().strip()

        if mode == "project":
            return await self._execute_project_mode(
                entry=entry,
                build_cmd=build_cmd,
                extra_flags=extra_flags,
                sanitizer=sanitizer,
                argv=argv,
                stdin=stdin,
                env_vars=env_vars,
                timeout=timeout,
            )

        # snippet 模式：需要拿到源码
        if file_path and not code:
            code = self._read_file(file_path)
            if code is None:
                return ToolResult(success=False, error=f"文件不存在: {file_path}")

        if not code:
            return ToolResult(success=False, error="snippet 模式必须提供 code 或 file_path")

        wrapped_code = self._build_wrapper_code(
            code, params, function_signature=function_signature
        )

        return await self._execute_snippet_mode(
            source=wrapped_code,
            extra_flags=extra_flags,
            sanitizer=sanitizer,
            argv=argv,
            stdin=stdin,
            env_vars=env_vars,
            timeout=timeout,
            file_hint=file_path,
            params=params,
        )

    # ---------- snippet 模式 ----------

    async def _execute_snippet_mode(
        self,
        source: str,
        extra_flags: Optional[str],
        sanitizer: str,
        argv: Optional[List[str]],
        stdin: Optional[str],
        env_vars: Optional[Dict[str, str]],
        timeout: int,
        file_hint: Optional[str],
        params: Optional[Dict[str, str]],
    ) -> ToolResult:
        src_path = f"/tmp/poc{self.FILE_EXTENSION}"
        bin_path = "/tmp/poc.bin"

        src_b64 = base64.b64encode(source.encode("utf-8")).decode("ascii")

        san_flags = self._sanitizer_flags(sanitizer)
        flags = f"-g -O0 {self.STD_FLAG} {san_flags}".strip()
        if extra_flags:
            flags += " " + extra_flags

        argv_str = " ".join(shlex.quote(a) for a in (argv or []))
        stdin_pipe = ""
        if stdin is not None:
            stdin_b64 = base64.b64encode(stdin.encode("utf-8")).decode("ascii")
            stdin_pipe = f" < <(echo {stdin_b64} | base64 -d)"

        # sh 里我们分三段：写源码 -> 编译 -> 运行 (即使编译失败也带出 stderr)
        shell_script = (
            f"set -o pipefail; "
            f"echo {src_b64} | base64 -d > {src_path} && "
            f"echo '--- COMPILE ---' >&2 && "
            f"{self.COMPILER} {flags} {src_path} -o {bin_path} 2>&1 1>/dev/null; "
            f"rc=$?; "
            f"if [ $rc -ne 0 ]; then echo \"[COMPILE_FAILED rc=$rc]\"; exit 90; fi; "
            f"echo '--- RUN ---'; "
            f"ASAN_OPTIONS='abort_on_error=0:halt_on_error=1:exitcode=42:print_stacktrace=1' "
            f"UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1' "
            f"{bin_path} {argv_str}{stdin_pipe}; "
            f"echo \"[RUN_EXIT=$?]\""
        )

        # bash 允许 process substitution
        command = f"bash -c {shlex.quote(shell_script)}"

        result = await self.sandbox_manager.execute_command(
            command=command,
            timeout=timeout,
            env=env_vars,
        )

        analysis = self._analyze_c_output(result, argv=argv)
        return self._format_result(
            result=result,
            analysis=analysis,
            mode="snippet",
            file_hint=file_hint,
            params=params,
            sanitizer=sanitizer,
            argv=argv,
        )

    # ---------- project 模式 ----------

    async def _execute_project_mode(
        self,
        entry: Optional[str],
        build_cmd: Optional[str],
        extra_flags: Optional[str],
        sanitizer: str,
        argv: Optional[List[str]],
        stdin: Optional[str],
        env_vars: Optional[Dict[str, str]],
        timeout: int,
    ) -> ToolResult:
        if not entry:
            return ToolResult(
                success=False,
                error="project 模式必须提供 entry (要跑的命令，例如 './poc-driver' 或 'make check')",
            )

        # 项目源码只读挂载到 /workspace
        host_workdir = os.path.abspath(self.project_root)
        if not os.path.isdir(host_workdir):
            return ToolResult(
                success=False,
                error=f"project_root 不是有效目录: {host_workdir}",
            )

        san_flags = self._sanitizer_flags(sanitizer)
        cflags = f"-g -O0 {san_flags}"
        if extra_flags:
            cflags += " " + extra_flags

        build_cmd = build_cmd or "make"

        stdin_pipe = ""
        if stdin is not None:
            stdin_b64 = base64.b64encode(stdin.encode("utf-8")).decode("ascii")
            stdin_pipe = f" < <(echo {stdin_b64} | base64 -d)"

        argv_str = " ".join(shlex.quote(a) for a in (argv or []))

        # 需要把只读的 /workspace 拷到可写的 /tmp/build 才能编译
        shell_script = (
            f"set -o pipefail; "
            f"cp -r /workspace /tmp/build && cd /tmp/build && "
            f"export CC={self.COMPILER} CXX=g++ CFLAGS='{cflags}' CXXFLAGS='{cflags}' "
            f"LDFLAGS='{san_flags}'; "
            f"echo '--- BUILD ---'; "
            f"{build_cmd}; brc=$?; "
            f"if [ $brc -ne 0 ]; then echo \"[BUILD_FAILED rc=$brc]\"; exit 90; fi; "
            f"echo '--- RUN ---'; "
            f"ASAN_OPTIONS='abort_on_error=0:halt_on_error=1:exitcode=42:print_stacktrace=1' "
            f"UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1' "
            f"{entry} {argv_str}{stdin_pipe}; "
            f"echo \"[RUN_EXIT=$?]\""
        )
        command = f"bash -c {shlex.quote(shell_script)}"

        # 用 execute_tool_command 走 host_workdir 只读挂载
        result = await self.sandbox_manager.execute_tool_command(
            command=command,
            host_workdir=host_workdir,
            timeout=timeout,
            env=env_vars,
            network_mode="none",
        )

        analysis = self._analyze_c_output(result, argv=argv)
        return self._format_result(
            result=result,
            analysis=analysis,
            mode="project",
            file_hint=None,
            params=None,
            sanitizer=sanitizer,
            argv=argv,
            entry=entry,
            build_cmd=build_cmd,
        )

    # ---------- 工具方法 ----------

    def _sanitizer_flags(self, sanitizer: str) -> str:
        s = (sanitizer or "").strip().lower()
        if s in ("", "none"):
            return ""
        # 允许 "address,undefined"
        parts = [p.strip() for p in s.split(",") if p.strip()]
        allowed = {"address", "undefined", "leak", "thread"}
        parts = [p for p in parts if p in allowed]
        if not parts:
            return ""
        return "-fsanitize=" + ",".join(parts)

    def _make_wrapper_from_signature(
        self,
        vuln_source: str,
        signature: str,
        params: Optional[Dict[str, str]],
    ) -> Optional[str]:
        """尝试根据 `int vuln(const char *s)` 这种签名生成一个 main() 调用者."""
        # 极简解析：抓函数名
        m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", signature)
        if not m:
            return None
        fname = m.group(1)

        # 从 params 里挑第一个作为字符串参数
        first_arg = ""
        if params:
            first_arg = next(iter(params.values()), "")

        arg_literal = json.dumps(first_arg)  # C 兼容的字符串字面量

        return (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            f"{vuln_source}\n\n"
            "int main(int argc, char **argv) {\n"
            f"    const char *user_input = argc > 1 ? argv[1] : {arg_literal};\n"
            f"    int rc = (int){fname}(user_input);\n"
            "    printf(\"[RESULT] rc=%d\\n\", rc);\n"
            "    return 0;\n"
            "}\n"
        )

    def _analyze_c_output(
        self,
        result: Dict[str, Any],
        argv: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """C 特有的漏洞证据检测."""
        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        combined = stdout + "\n" + stderr
        combined_lower = combined.lower()

        indicators = [
            (r"AddressSanitizer:\s*heap-buffer-overflow", "堆缓冲区溢出 (ASAN)"),
            (r"AddressSanitizer:\s*stack-buffer-overflow", "栈缓冲区溢出 (ASAN)"),
            (r"AddressSanitizer:\s*global-buffer-overflow", "全局缓冲区溢出 (ASAN)"),
            (r"AddressSanitizer:\s*heap-use-after-free", "Use-After-Free (ASAN)"),
            (r"AddressSanitizer:\s*double-free", "Double-Free (ASAN)"),
            (r"AddressSanitizer:\s*SEGV", "段错误 (ASAN)"),
            (r"AddressSanitizer:\s*stack-overflow", "栈溢出 (ASAN)"),
            (r"AddressSanitizer:", "AddressSanitizer 命中"),
            (r"UndefinedBehaviorSanitizer:", "未定义行为 (UBSAN)"),
            (r"LeakSanitizer: detected memory leaks", "内存泄漏 (LSAN)"),
            (r"runtime error:", "运行时错误 (UBSAN)"),
        ]
        for pattern, desc in indicators:
            if re.search(pattern, combined, re.IGNORECASE):
                return {"is_vulnerable": True, "evidence": desc}

        # 段错误 / abort
        if re.search(r"segmentation fault|signal 11|core dumped", combined_lower):
            return {"is_vulnerable": True, "evidence": "段错误 / signal 11"}
        if re.search(r"\baborted\b|signal 6\b", combined_lower):
            return {"is_vulnerable": True, "evidence": "abort() / signal 6"}

        # 命令注入：如果 argv 触发了 shell，会出现 uid=/root:
        cmd_indicators = [
            ("uid=", "命令执行成功 (uid= 出现)"),
            ("root:", "命令执行成功 (/etc/passwd 泄露)"),
        ]
        for indicator, desc in cmd_indicators:
            if indicator in combined_lower:
                return {"is_vulnerable": True, "evidence": desc}

        return {"is_vulnerable": False, "evidence": None}

    def _format_result(
        self,
        result: Dict[str, Any],
        analysis: Dict[str, Any],
        mode: str,
        file_hint: Optional[str],
        params: Optional[Dict[str, str]],
        sanitizer: str,
        argv: Optional[List[str]],
        entry: Optional[str] = None,
        build_cmd: Optional[str] = None,
    ) -> ToolResult:
        parts: List[str] = [f"⚙️ {self.LANGUAGE_NAME} 测试结果 ({mode} 模式)\n"]
        if file_hint:
            parts.append(f"源文件: {file_hint}")
        if mode == "project":
            parts.append(f"构建: {build_cmd or 'make'}")
            parts.append(f"入口: {entry}")
        parts.append(f"Sanitizer: {sanitizer or 'none'}")
        if argv:
            parts.append(f"argv: {argv}")
        if params:
            parts.append(f"params: {json.dumps(params, ensure_ascii=False)}")

        parts.append(f"\n退出码: {result.get('exit_code')}")

        if result.get("stdout"):
            parts.append(f"\n输出:\n```\n{result['stdout'][:3000]}\n```")
        if result.get("stderr"):
            parts.append(f"\n错误:\n```\n{result['stderr'][:3000]}\n```")

        if analysis["is_vulnerable"]:
            parts.append(f"\n🔴 **漏洞已触发**: {analysis['evidence']}")
        else:
            # C 项目 verification 的关键：即使未触发，也留下"已尝试"证据
            parts.append("\n🟡 未触发漏洞特征（编译/运行日志见上）")

        return ToolResult(
            success=True,
            data="\n".join(parts),
            metadata={
                "language": self.LANGUAGE_NAME,
                "mode": mode,
                "exit_code": result.get("exit_code"),
                "is_vulnerable": analysis["is_vulnerable"],
                "evidence": analysis["evidence"],
                "sanitizer": sanitizer,
            },
        )


# ============================================================
# 具体工具
# ============================================================

class CTestTool(BaseCTestTool):
    """C 代码测试工具 (gcc + AddressSanitizer)."""

    COMPILER = "gcc"
    STD_FLAG = "-std=c11"
    FILE_EXTENSION = ".c"
    LANGUAGE_NAME = "C"

    @property
    def name(self) -> str:
        return "c_test"

    @property
    def description(self) -> str:
        return """在沙箱中编译并运行 C 代码，可开 AddressSanitizer 生成内存类漏洞证据。

输入:
- mode: "snippet" (默认，单文件 PoC) | "project" (整个仓库 configure+make)
- code / file_path: snippet 模式下的源码
- function_signature: 可选，若给出漏洞函数原型，会自动生成 main() 调用者
- sanitizer: "address" (默认) | "undefined" | "address,undefined" | "none"
- argv: 传给可执行文件的 argv 列表
- stdin: 传给可执行文件的 stdin 内容
- extra_flags: 额外编译参数，例如 "-lssl -lcrypto"
- 【project 模式】
  - build_cmd: 构建命令，默认 "make"，可写 "./configure && make"
  - entry: 要跑的可执行文件路径 (相对 /tmp/build)，例如 "./poc-driver"
- timeout: 秒 (默认 60，project 模式建议 300+)

示例:
1. snippet 内存越界 PoC:
   {"mode":"snippet","code":"#include<string.h>\\nint main(){char b[8];strcpy(b,\\"AAAAAAAAAAAAAAAAAAAA\\");return 0;}"}
2. snippet 用签名自动包 main:
   {"mode":"snippet","code":"int vuln(const char*s){char buf[8];strcpy(buf,s);return 0;}","function_signature":"int vuln(const char*)","params":{"input":"A"*40}}
3. project 模式跑 openvpn 目录里的 driver:
   {"mode":"project","build_cmd":"./configure && make","entry":"./sample/poc-driver","timeout":600}"""

    @property
    def args_schema(self):
        return CTestInput


class CppTestTool(BaseCTestTool):
    """C++ 代码测试工具 (g++ + AddressSanitizer)."""

    COMPILER = "g++"
    STD_FLAG = "-std=c++17"
    FILE_EXTENSION = ".cpp"
    LANGUAGE_NAME = "C++"

    @property
    def name(self) -> str:
        return "cpp_test"

    @property
    def description(self) -> str:
        return """在沙箱中编译并运行 C++ 代码，可开 AddressSanitizer / UBSan。

参数与 c_test 完全一致（除了默认 std=c++17，编译器为 g++）。
适用于 STL / iostream / 模板漏洞场景。"""

    @property
    def args_schema(self):
        return CTestInput


# ============================================================
# FuzzTestTool (libFuzzer)
# ============================================================

class FuzzTestInput(BaseModel):
    harness_code: str = Field(
        ...,
        description=(
            "libFuzzer harness 代码，必须实现 LLVMFuzzerTestOneInput。"
            "可以直接把项目里的函数 include/复制进来。"
        ),
    )
    language: str = Field(default="c", description="c 或 cpp")
    extra_flags: Optional[str] = Field(
        default=None,
        description="额外编译参数，例如 '-I/workspace/include -lssl'",
    )
    max_total_time: int = Field(default=30, description="fuzz 最长秒数 (默认 30)")
    max_len: int = Field(default=4096, description="单个输入最大字节数")
    seed_corpus: Optional[List[str]] = Field(
        default=None,
        description="可选，初始语料 (base64 编码)",
    )


class FuzzTestTool(AgentTool):
    """使用 clang + libFuzzer + AddressSanitizer 对目标函数做短时 fuzz.

    对 openvpn 这种项目，30s-2min 的短 fuzz 通常足以出真实的崩溃/ASAN 证据。
    """

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        project_root: str = ".",
    ):
        super().__init__()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.project_root = project_root

    @property
    def name(self) -> str:
        return "fuzz_test"

    @property
    def description(self) -> str:
        return """使用 clang libFuzzer + AddressSanitizer 对目标函数做短时 fuzzing。

输入:
- harness_code: libFuzzer harness，必须包含:
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { ... }
- language: "c" (默认) | "cpp"
- max_total_time: fuzz 最长秒数 (默认 30，建议 30-120)
- max_len: 输入最大字节数 (默认 4096)
- extra_flags: 额外编译参数
- seed_corpus: 可选，初始 base64 语料列表

输出:
- 编译日志 + fuzz 运行日志 + 若崩溃则附 ASAN 报告和 crash 输入 (hex)

典型 harness 示例:
```c
#include <stdint.h>
#include <string.h>
extern int vuln(const char *s);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    char *buf = (char*)malloc(size + 1);
    memcpy(buf, data, size); buf[size] = 0;
    vuln(buf);
    free(buf);
    return 0;
}
```"""

    @property
    def args_schema(self):
        return FuzzTestInput

    async def _execute(
        self,
        harness_code: str,
        language: str = "c",
        extra_flags: Optional[str] = None,
        max_total_time: int = 30,
        max_len: int = 4096,
        seed_corpus: Optional[List[str]] = None,
        **kwargs,
    ) -> ToolResult:
        try:
            await self.sandbox_manager.initialize()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Sandbox init failed: {e}")

        if not self.sandbox_manager.is_available:
            return ToolResult(success=False, error="沙箱环境不可用 (Docker Unavailable)")

        lang = (language or "c").lower().strip()
        compiler = "clang" if lang == "c" else "clang++"
        src_ext = ".c" if lang == "c" else ".cpp"
        std_flag = "-std=c11" if lang == "c" else "-std=c++17"

        src_b64 = base64.b64encode(harness_code.encode("utf-8")).decode("ascii")

        # 语料准备
        corpus_setup = "mkdir -p /tmp/corpus"
        if seed_corpus:
            for i, seed in enumerate(seed_corpus):
                corpus_setup += (
                    f" && echo {shlex.quote(seed)} | base64 -d > /tmp/corpus/seed_{i}.bin"
                )

        san_flags = "-fsanitize=fuzzer,address,undefined"
        cflags = f"-g -O1 {std_flag} {san_flags}"
        if extra_flags:
            cflags += " " + extra_flags

        # libFuzzer 内部时间上限；再套一个 shell timeout 兜底
        wall_timeout = max_total_time + 30
        shell_script = (
            f"set -o pipefail; "
            f"echo {src_b64} | base64 -d > /tmp/harness{src_ext} && "
            f"{corpus_setup} && "
            f"echo '--- COMPILE ---'; "
            f"{compiler} {cflags} /tmp/harness{src_ext} -o /tmp/fuzz 2>&1; "
            f"crc=$?; "
            f"if [ $crc -ne 0 ]; then echo \"[COMPILE_FAILED rc=$crc]\"; exit 90; fi; "
            f"echo '--- FUZZ ---'; "
            f"ASAN_OPTIONS='abort_on_error=0:halt_on_error=1:print_stacktrace=1' "
            f"/tmp/fuzz /tmp/corpus "
            f"-max_total_time={max_total_time} -max_len={max_len} "
            f"-artifact_prefix=/tmp/crash- -print_final_stats=1 2>&1; "
            f"echo \"[FUZZ_EXIT=$?]\"; "
            f"echo '--- CRASH ARTIFACTS ---'; "
            f"for f in /tmp/crash-*; do "
            f"  if [ -f \"$f\" ]; then echo \"[CRASH: $f]\"; xxd \"$f\" | head -40; fi; "
            f"done"
        )
        command = f"bash -c {shlex.quote(shell_script)}"

        result = await self.sandbox_manager.execute_command(
            command=command,
            timeout=wall_timeout,
        )

        stdout = result.get("stdout", "") or ""
        stderr = result.get("stderr", "") or ""
        combined = stdout + "\n" + stderr

        crashed = bool(re.search(r"AddressSanitizer:|SUMMARY: |\[CRASH: ", combined))
        # libFuzzer 崩溃退出码通常非 0
        exit_code = result.get("exit_code", 0)

        parts = [
            "🎯 libFuzzer 测试结果\n",
            f"语言: {lang}",
            f"编译器: {compiler}",
            f"max_total_time: {max_total_time}s",
            f"max_len: {max_len}",
            f"退出码: {exit_code}",
        ]
        if stdout:
            parts.append(f"\n输出:\n```\n{stdout[:5000]}\n```")
        if stderr:
            parts.append(f"\n错误:\n```\n{stderr[:3000]}\n```")

        if crashed:
            parts.append("\n🔴 **Fuzz 命中崩溃** — 见上方 ASAN / crash artifact")
        else:
            parts.append("\n🟡 未在时间窗内触发崩溃 (可能需要更长时间或更好的 harness)")

        return ToolResult(
            success=True,
            data="\n".join(parts),
            metadata={
                "language": lang,
                "exit_code": exit_code,
                "crashed": crashed,
                "max_total_time": max_total_time,
            },
        )
