"""
Agent 注册表和动态Agent树管理

提供：
- Agent实例注册和管理
- 动态Agent树结构
- Agent状态追踪
- 子Agent创建和销毁

🔥 并发隔离：每个任务持有独立的 AgentRegistry 实例
   - 通过 contextvars.ContextVar 绑定到当前 asyncio task
   - 全局 `agent_registry` 是路由代理，所有调用会转发到当前 context 的 registry
   - 兼容旧代码：老的 `agent_registry.xxx()` 调用无需修改
"""

import logging
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .state import AgentState

logger = logging.getLogger(__name__)


class AgentRegistry:
    """
    Agent 注册表
    
    管理所有Agent实例，维护动态Agent树结构
    """
    
    def __init__(self):
        self._lock = threading.RLock()
        
        # Agent图结构
        self._agent_graph: Dict[str, Any] = {
            "nodes": {},  # agent_id -> node_info
            "edges": [],  # {from, to, type}
        }
        
        # Agent实例和状态
        self._agent_instances: Dict[str, Any] = {}  # agent_id -> agent_instance
        self._agent_states: Dict[str, "AgentState"] = {}  # agent_id -> state
        
        # 消息队列
        self._agent_messages: Dict[str, List[Dict[str, Any]]] = {}  # agent_id -> messages
        
        # 根Agent
        self._root_agent_id: Optional[str] = None
        
        # 运行中的Agent线程
        self._running_agents: Dict[str, threading.Thread] = {}
    
    # ============ Agent 注册 ============
    
    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        agent_instance: Any = None,
        state: Optional["AgentState"] = None,
        knowledge_modules: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        注册Agent到注册表
        
        Args:
            agent_id: Agent唯一标识
            agent_name: Agent名称
            agent_type: Agent类型
            task: 任务描述
            parent_id: 父Agent ID
            agent_instance: Agent实例
            state: Agent状态
            knowledge_modules: 加载的知识模块
            
        Returns:
            注册的节点信息
        """
        logger.info(f"[AgentRegistry] register_agent 被调用: {agent_name} (id={agent_id}, parent={parent_id})")
        logger.info(f"[AgentRegistry] 当前节点数: {len(self._agent_graph['nodes'])}, 节点列表: {list(self._agent_graph['nodes'].keys())}")
        
        with self._lock:
            node = {
                "id": agent_id,
                "name": agent_name,
                "type": agent_type,
                "task": task,
                "status": "running",
                "parent_id": parent_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "result": None,
                "knowledge_modules": knowledge_modules or [],
                "children": [],
            }
            
            self._agent_graph["nodes"][agent_id] = node
            
            if agent_instance:
                self._agent_instances[agent_id] = agent_instance
            
            if state:
                self._agent_states[agent_id] = state
            
            # 初始化消息队列
            if agent_id not in self._agent_messages:
                self._agent_messages[agent_id] = []
            
            # 添加边（父子关系）
            if parent_id:
                self._agent_graph["edges"].append({
                    "from": parent_id,
                    "to": agent_id,
                    "type": "delegation",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
                
                # 更新父节点的children列表
                if parent_id in self._agent_graph["nodes"]:
                    self._agent_graph["nodes"][parent_id]["children"].append(agent_id)
            
            # 设置根Agent
            if parent_id is None and self._root_agent_id is None:
                self._root_agent_id = agent_id
            
            logger.info(f"[AgentRegistry] 注册完成: {agent_name} ({agent_id}), parent: {parent_id}")
            logger.info(f"[AgentRegistry] 注册后节点数: {len(self._agent_graph['nodes'])}, 节点列表: {list(self._agent_graph['nodes'].keys())}")
            return node
    
    def unregister_agent(self, agent_id: str) -> None:
        """注销Agent"""
        with self._lock:
            if agent_id in self._agent_graph["nodes"]:
                del self._agent_graph["nodes"][agent_id]
            
            self._agent_instances.pop(agent_id, None)
            self._agent_states.pop(agent_id, None)
            self._agent_messages.pop(agent_id, None)
            self._running_agents.pop(agent_id, None)
            
            # 移除相关边
            self._agent_graph["edges"] = [
                e for e in self._agent_graph["edges"]
                if e["from"] != agent_id and e["to"] != agent_id
            ]
            
            logger.debug(f"Unregistered agent: {agent_id}")
    
    # ============ Agent 状态更新 ============
    
    def update_agent_status(
        self,
        agent_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """更新Agent状态"""
        with self._lock:
            if agent_id in self._agent_graph["nodes"]:
                node = self._agent_graph["nodes"][agent_id]
                node["status"] = status
                
                if status in ["completed", "failed", "stopped"]:
                    node["finished_at"] = datetime.now(timezone.utc).isoformat()
                
                if result:
                    node["result"] = result
                
                logger.debug(f"Updated agent {agent_id} status to {status}")
    
    def get_agent_status(self, agent_id: str) -> Optional[str]:
        """获取Agent状态"""
        with self._lock:
            if agent_id in self._agent_graph["nodes"]:
                return self._agent_graph["nodes"][agent_id]["status"]
            return None
    
    # ============ Agent 查询 ============
    
    def get_agent(self, agent_id: str) -> Optional[Any]:
        """获取Agent实例"""
        return self._agent_instances.get(agent_id)
    
    def get_agent_state(self, agent_id: str) -> Optional["AgentState"]:
        """获取Agent状态"""
        return self._agent_states.get(agent_id)
    
    def get_agent_node(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """获取Agent节点信息"""
        return self._agent_graph["nodes"].get(agent_id)
    
    def get_root_agent_id(self) -> Optional[str]:
        """获取根Agent ID"""
        return self._root_agent_id
    
    def get_children(self, agent_id: str) -> List[str]:
        """获取子Agent ID列表"""
        with self._lock:
            node = self._agent_graph["nodes"].get(agent_id)
            if node:
                return node.get("children", [])
            return []
    
    def get_parent(self, agent_id: str) -> Optional[str]:
        """获取父Agent ID"""
        with self._lock:
            node = self._agent_graph["nodes"].get(agent_id)
            if node:
                return node.get("parent_id")
            return None
    
    # ============ Agent 树操作 ============
    
    def get_agent_tree(self) -> Dict[str, Any]:
        """获取完整的Agent树结构"""
        with self._lock:
            return {
                "nodes": dict(self._agent_graph["nodes"]),
                "edges": list(self._agent_graph["edges"]),
                "root_agent_id": self._root_agent_id,
            }
    
    def get_agent_tree_view(self, agent_id: Optional[str] = None) -> str:
        """获取Agent树的文本视图"""
        with self._lock:
            lines = ["=== AGENT TREE ==="]
            
            root_id = agent_id or self._root_agent_id
            if not root_id or root_id not in self._agent_graph["nodes"]:
                return "No agents in the tree"
            
            def _build_tree(aid: str, depth: int = 0) -> None:
                node = self._agent_graph["nodes"].get(aid)
                if not node:
                    return
                
                indent = "  " * depth
                status_emoji = {
                    "running": "🔄",
                    "waiting": "⏳",
                    "completed": "✅",
                    "failed": "❌",
                    "stopped": "🛑",
                }.get(node["status"], "❓")
                
                lines.append(f"{indent}{status_emoji} {node['name']} ({aid})")
                lines.append(f"{indent}   Task: {node['task'][:50]}...")
                lines.append(f"{indent}   Status: {node['status']}")
                
                if node.get("knowledge_modules"):
                    lines.append(f"{indent}   Modules: {', '.join(node['knowledge_modules'])}")
                
                for child_id in node.get("children", []):
                    _build_tree(child_id, depth + 1)
            
            _build_tree(root_id)
            return "\n".join(lines)
    
    def get_statistics(self) -> Dict[str, int]:
        """获取统计信息"""
        with self._lock:
            stats = {
                "total": len(self._agent_graph["nodes"]),
                "running": 0,
                "waiting": 0,
                "completed": 0,
                "failed": 0,
                "stopped": 0,
            }
            
            for node in self._agent_graph["nodes"].values():
                status = node.get("status", "unknown")
                if status in stats:
                    stats[status] += 1
            
            return stats
    
    # ============ 清理 ============
    
    def clear(self) -> None:
        """清空注册表"""
        import traceback
        stack_summary = "".join(traceback.format_stack(limit=6))
        with self._lock:
            n_before = len(self._agent_graph["nodes"])
            self._agent_graph = {"nodes": {}, "edges": []}
            self._agent_instances.clear()
            self._agent_states.clear()
            self._agent_messages.clear()
            self._running_agents.clear()
            self._root_agent_id = None
            logger.warning(
                f"[AgentRegistry] ⚠️ clear() 调用：清空了 {n_before} 个节点。调用栈:\n{stack_summary}"
            )
    
    def cleanup_finished_agents(self) -> int:
        """清理已完成的Agent"""
        with self._lock:
            finished_ids = [
                aid for aid, node in self._agent_graph["nodes"].items()
                if node["status"] in ["completed", "failed", "stopped"]
            ]
            
            for aid in finished_ids:
                # 保留节点信息，但清理实例
                self._agent_instances.pop(aid, None)
                self._running_agents.pop(aid, None)
            
            return len(finished_ids)


# 全局注册表实例（fallback，用于没设置 context 的场景）
_DEFAULT_REGISTRY = AgentRegistry()

# 🔥 per-task registry storage: task_id -> AgentRegistry
_task_registries: Dict[str, AgentRegistry] = {}
_task_registries_lock = threading.RLock()

# 🔥 当前任务的 registry —— 通过 ContextVar 绑定到 asyncio task
_current_registry: ContextVar[Optional[AgentRegistry]] = ContextVar(
    "current_agent_registry", default=None
)


def get_registry_for_task(task_id: str) -> AgentRegistry:
    """获取（或创建）指定任务的 registry。同一 task_id 每次返回同一个实例。"""
    with _task_registries_lock:
        reg = _task_registries.get(task_id)
        if reg is None:
            reg = AgentRegistry()
            _task_registries[task_id] = reg
            logger.info(f"[AgentRegistry] 🔧 创建 per-task registry: task_id={task_id}")
        return reg


def bind_registry_to_task(task_id: str) -> AgentRegistry:
    """
    把指定任务的 registry 绑定到当前 asyncio context。

    调用后，本 context 内所有 `agent_registry.xxx()` 调用都会路由到这个 registry。
    应该在任务开始时（例如 orchestrator 注册前）调用。
    """
    reg = get_registry_for_task(task_id)
    _current_registry.set(reg)
    logger.info(f"[AgentRegistry] 🔗 绑定 registry 到当前 context: task_id={task_id}")
    return reg


def release_registry_for_task(task_id: str) -> None:
    """释放指定任务的 registry，防止内存泄漏。任务结束时调用。"""
    with _task_registries_lock:
        removed = _task_registries.pop(task_id, None)
        if removed is not None:
            n = len(removed._agent_graph["nodes"])
            logger.info(f"[AgentRegistry] 🗑️  释放 per-task registry: task_id={task_id}, 清理 {n} 个节点")


def _resolve_current_registry() -> AgentRegistry:
    """
    解析当前 context 应该使用哪个 registry。

    优先级：context 绑定的 > 默认全局。
    如果 context 里没绑定（比如非任务代码路径），返回默认 registry。
    """
    reg = _current_registry.get()
    if reg is not None:
        return reg
    return _DEFAULT_REGISTRY


class _AgentRegistryProxy:
    """
    🔥 路由代理：把所有属性/方法访问转发到当前 context 的 registry。

    这样老代码 `from ... import agent_registry` + `agent_registry.register_agent(...)`
    无需修改，就能自动隔离到 per-task registry。
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(_resolve_current_registry(), name)

    def __repr__(self) -> str:
        return f"<AgentRegistryProxy → {_resolve_current_registry()!r}>"


# 全局导出的 agent_registry 现在是 proxy，而非真实 registry 实例
agent_registry = _AgentRegistryProxy()
