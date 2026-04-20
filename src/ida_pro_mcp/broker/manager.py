"""Broker 架构管理 (纯路由)

Broker 进程在此仅做：
1. 请求透传：把 Cursor 发来的 tools/call / resources/read 等请求通过 SSE
   推送给目标 IDA 实例，并把响应原样带回。
2. tools/list 装饰：替换 IDA 工具的 schema，并**追加**两个"虚拟工具"
   (`refresh_cache`, `cache_status`) 的 schema 给大模型看见。

真正的缓存读写 (SQLite) 工作在 IDA 插件进程中完成，Broker 进程严禁
import `sqlite_cache` / `sqlite_query`，避免污染路由职责。
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import TYPE_CHECKING, Optional, cast

from .client import BrokerClient
from .cache_types import ToolInputSchema, ToolSchema

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse
else:
    JsonRpcResponse = dict


_broker_client: Optional[BrokerClient] = None


def get_broker_client(broker_url: Optional[str] = None) -> BrokerClient:
    """获取 Broker 客户端，MCP 模式下必有。"""
    global _broker_client
    if _broker_client is None:
        _broker_client = BrokerClient(
            broker_url or os.environ.get("IDA_MCP_BROKER_URL", "http://127.0.0.1:13337"),
            10.0,
        )
    return _broker_client


# ---------------------------------------------------------------------------
# 虚拟缓存工具 Schema (仅由 Broker 在 tools/list 里插入，不在 Broker 执行)
# ---------------------------------------------------------------------------


_INSTANCE_ID_PROP: dict[str, str] = {
    "type": "string",
    "description": (
        "必须提供的 instance_id（或 client_id），用于将请求精确路由到特定的 IDA 实例。"
        "请先调用 instance_list 查看并选择合适的客户端 ID。"
    ),
}


def _build_cache_tool_schemas() -> list[ToolSchema]:
    """生成 refresh_cache / cache_status 两个虚拟工具的 MCP schema。"""
    refresh_input: ToolInputSchema = {
        "type": "object",
        "properties": {"instance_id": dict(_INSTANCE_ID_PROP)},
        "required": ["instance_id"],
    }
    status_input: ToolInputSchema = {
        "type": "object",
        "properties": {"instance_id": dict(_INSTANCE_ID_PROP)},
        "required": ["instance_id"],
    }
    return [
        {
            "name": "refresh_cache",
            "description": (
                "请求指定 IDA 实例立即刷新其本地 SQLite 静态缓存 (xxx.idb.mcp.sqlite)。"
                "实际刷新仍然需要 IDA 进入 idle 状态才会执行，此工具仅唤醒插件端守护线程并立即返回。"
            ),
            "inputSchema": refresh_input,
        },
        {
            "name": "cache_status",
            "description": (
                "查询指定 IDA 实例的本地 SQLite 静态缓存状态 (status / last_updated / 各表计数)。"
                "当 status != 'ready' 时，find_regex / entity_query / list_funcs / list_globals / imports 等工具将返回错误并提示稍后重试。"
            ),
            "inputSchema": status_input,
        },
    ]


# ---------------------------------------------------------------------------
# 实例管理工具
# ---------------------------------------------------------------------------


def register_broker_tools(mcp):
    """注册实例管理工具（通过 Broker 客户端，无需本地 REGISTRY）。"""

    @mcp.tool
    def instance_list() -> list[dict]:
        """列出所有已连接的 IDA/Hopper 实例。无需加载 IDB。返回 instance_id,name,binary_path,idb_path,base_addr。"""
        return get_broker_client().list_instances()

    @mcp.tool
    def instance_info(instance_id: str) -> dict:
        """获取指定实例详情。instance_id 来自 instance_list。返回 binary_path,idb_path,base_addr,processor 等。"""
        instances = get_broker_client().list_instances()
        for inst in instances:
            if inst.get("instance_id") == instance_id:
                return inst
        return {"error": f"实例不存在: {instance_id}"}


# ---------------------------------------------------------------------------
# 请求路由：原样转发到目标 IDA
# ---------------------------------------------------------------------------


def route_to_ida(request: dict) -> JsonRpcResponse | None:
    """将请求路由到指定的 IDA 实例 (通过 Broker)。"""
    broker = get_broker_client()
    if not broker.has_instances():
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。",
            },
            "id": request.get("id"),
        }

    instance_id: Optional[str] = None
    if request.get("method") == "tools/call":
        params = request.get("params", {}) or {}
        args = params.get("arguments", {}) or {}
        if "instance_id" not in args:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32602,
                    "message": "必须提供 instance_id 参数。请先调用 instance_list 查看并选择合适的客户端 ID。",
                },
                "id": request.get("id"),
            }
        # 提取并移除 instance_id，避免发给 IDA 的真实参数出现多余字段
        instance_id = args.pop("instance_id")
    # 对于非 tool/call 请求 (例如 resources/read)，由 Broker 根据在册实例数自动选择。

    response = broker.send_request(request, instance_id)
    if response is None:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "IDA 请求超时"},
            "id": request.get("id"),
        }
    return cast(JsonRpcResponse, response)


# ---------------------------------------------------------------------------
# dispatch 代理
# ---------------------------------------------------------------------------


def setup_dispatch_proxy(mcp, original_dispatch, ida_tools, ida_tool_schemas):
    """设置代理 dispatch：IDA 工具 → 转发，其他 → 本地处理。"""

    # Broker 进程生成虚拟工具 schema；名称也加进 ida_tools，使得 tools/call 走路由而不是原 dispatch
    extra_cache_schemas: list[ToolSchema] = _build_cache_tool_schemas()
    extra_cache_names: set[str] = {s["name"] for s in extra_cache_schemas}

    def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        if isinstance(request, dict):
            req: dict = request
        else:
            req = json.loads(request)

        method = req.get("method", "")

        # 本地协议方法
        if method in {"initialize", "ping"} or method.startswith("notifications/"):
            return original_dispatch(req)

        # tools/call - 判断是否需要转发给 IDA
        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "") if isinstance(params, dict) else ""

            if tool_name in ida_tools or tool_name in extra_cache_names:
                return route_to_ida(req)

            return original_dispatch(req)

        # tools/list - 先用上游 dispatch，再覆盖 IDA 工具 schema，然后追加虚拟工具
        if method == "tools/list":
            response = original_dispatch(req)
            tools = response.get("result", {}).get("tools", []) if response else []
            for i, tool in enumerate(tools):
                if tool.get("name") in ida_tool_schemas:
                    tools[i] = ida_tool_schemas[tool["name"]]
            # 追加虚拟缓存工具 schema
            existing_names = {t.get("name") for t in tools}
            for schema in extra_cache_schemas:
                if schema["name"] not in existing_names:
                    tools.append(cast(dict, schema))

            broker = get_broker_client()
            instances = broker.list_instances()
            if instances:
                print(
                    f"[MCP] tools/list: {len(tools)} 个工具 (活跃 IDA 实例数: {len(instances)})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[MCP] tools/list: {len(tools)} 个工具 (等待 IDA 连接)",
                    file=sys.stderr,
                )
            return response

        # resources 相关
        if method == "resources/list":
            return original_dispatch(req)
        if method == "resources/templates/list":
            return original_dispatch(req)
        if method == "resources/read":
            if not get_broker_client().has_instances():
                return cast(
                    JsonRpcResponse,
                    {"jsonrpc": "2.0", "result": {"contents": []}, "id": req.get("id")},
                )
            return route_to_ida(req)

        # prompts 相关
        if method in {"prompts/list", "prompts/get"}:
            return original_dispatch(req)

        # 其他请求转发到 IDA
        return route_to_ida(req)

    mcp.registry.dispatch = dispatch_proxy


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def run_broker(port: int):
    """启动 Broker 服务器，阻塞主线程。"""
    from .server import IDAHttpServer

    server = IDAHttpServer(port=port)
    server.start()
    print("[MCP] Broker 已启动，按 Ctrl+C 停止", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
