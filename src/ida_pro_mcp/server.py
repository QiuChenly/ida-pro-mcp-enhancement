"""IDA Pro MCP Server

Broker 架构:
  - Broker 模式 (--broker): 仅启动 HTTP，持有 REGISTRY，IDA 与 MCP 客户端均连此进程。
  - MCP 模式 (默认): 仅 stdio，不绑定端口，通过 Broker 客户端请求 Broker。

  Cursor --stdio--> server.py --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
"""

import os
import sys
import json
import argparse
import threading
import time
from typing import Optional, BinaryIO

# 处理直接运行和作为包运行两种情况
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(SCRIPT_DIR))
    from ida_pro_mcp.http_server import IDAHttpServer, REGISTRY
    from ida_pro_mcp.tool_registry import parse_all_api_files, ToolDef
    from ida_pro_mcp.install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from ida_pro_mcp.broker_client import BrokerClient
else:
    from .http_server import IDAHttpServer, REGISTRY
    from .tool_registry import parse_all_api_files, ToolDef
    from .install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from .broker_client import BrokerClient

# 导入 MCP 实现
sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer
from zeromcp.jsonrpc import JsonRpcResponse
sys.path.pop(0)


# ============================================================================
# stdio 输出（用于发送通知）
# ============================================================================

_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: dict = None):
    """发送 MCP 通知到客户端（stdio）"""
    if _stdio_stdout is None:
        return
    
    notification = {"jsonrpc": "2.0", "method": method}
    if params:
        notification["params"] = params
    
    try:
        with _stdio_lock:
            _stdio_stdout.write(json.dumps(notification).encode("utf-8") + b"\n")
            _stdio_stdout.flush()
    except Exception as e:
        print(f"[MCP] 发送通知失败: {e}", file=sys.stderr)


# ============================================================================
# MCP 服务器
# ============================================================================

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# HTTP 服务器实例（仅 Broker 模式使用）
HTTP_SERVER: Optional[IDAHttpServer] = None

# Broker 客户端（MCP 模式使用，向 Broker 请求实例列表与转发 IDA 请求）
_broker_client: Optional[BrokerClient] = None


def _broker():
    """获取 Broker 客户端，MCP 模式下必有"""
    global _broker_client
    if _broker_client is None:
        _broker_client = BrokerClient(
            os.environ.get("IDA_MCP_BROKER_URL", "http://127.0.0.1:13337"),
            10.0,
        )
    return _broker_client


# 注册实例管理工具（通过 Broker 客户端，无需本地 REGISTRY）
@mcp.tool
def instance_list() -> list[dict]:
    """列出所有已连接的 IDA 实例。本地工具，无需 IDA 连接。"""
    return _broker().list_instances()


@mcp.tool
def instance_current() -> dict:
    """获取当前活动 IDA 实例的信息。本地工具，无需 IDA 连接。"""
    out = _broker().get_current()
    if out is None:
        return {"error": "Broker 不可用。请先启动: ida-pro-mcp --broker"}
    if out.get("error"):
        return {"error": out["error"]}
    return out


@mcp.tool
def instance_switch(instance_id: str) -> dict:
    """切换到指定的 IDA 实例。本地工具，无需 IDA 连接。"""
    return _broker().set_current(instance_id)


@mcp.tool
def instance_info(instance_id: str) -> dict:
    """获取指定 IDA 实例的详细信息。本地工具，无需 IDA 连接。"""
    instances = _broker().list_instances()
    current = _broker().get_current()
    current_id = (current or {}).get("instance_id")
    for inst in instances:
        if inst.get("instance_id") == instance_id:
            return {**inst, "is_current": inst.get("instance_id") == current_id}
    return {"error": f"实例不存在: {instance_id}"}


# ============================================================================
# 动态注册 IDA 工具和资源
# ============================================================================

_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """为 IDA 工具创建 wrapper 函数"""
    from typing import Annotated, Any as AnyType
    
    def wrapper(**kwargs):
        pass
    
    wrapper.__name__ = tool_def.name
    wrapper.__doc__ = tool_def.description
    
    annotations = {}
    for param in tool_def.params:
        annotations[param.name] = Annotated[AnyType, param.description]
    annotations["return"] = AnyType
    wrapper.__annotations__ = annotations
    
    return wrapper


def _register_ida_tools(enable_unsafe: bool = False):
    """注册所有 IDA 工具到 MCP 服务器"""
    global IDA_TOOLS, _UNSAFE_ENABLED
    _UNSAFE_ENABLED = enable_unsafe
    
    registered_count = 0
    skipped_unsafe = 0
    
    for tool_def in _IDA_TOOLS:
        if tool_def.is_unsafe and not enable_unsafe:
            skipped_unsafe += 1
            continue
        
        IDA_TOOLS.add(tool_def.name)
        mcp.tools.methods[tool_def.name] = _create_ida_tool_wrapper(tool_def)
        registered_count += 1
    
    if skipped_unsafe > 0:
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具 (跳过 {skipped_unsafe} 个 unsafe 工具)", file=sys.stderr)
    else:
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具", file=sys.stderr)


def _register_ida_resources():
    """注册所有 IDA 资源到 MCP 服务器"""
    for res_def in _IDA_RESOURCES:
        def make_wrapper(uri):
            def wrapper(**kwargs):
                pass
            wrapper.__name__ = res_def.name
            wrapper.__doc__ = res_def.description
            setattr(wrapper, "__resource_uri__", uri)
            return wrapper
        
        mcp.resources.methods[res_def.name] = make_wrapper(res_def.uri)
    
    print(f"[MCP] 注册了 {len(_IDA_RESOURCES)} 个 IDA 资源", file=sys.stderr)


# ============================================================================
# 请求路由
# ============================================================================

def route_to_ida(request: dict) -> Optional[dict]:
    """将请求路由到当前 IDA 实例（通过 Broker）"""
    if not _broker().has_instances():
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。",
            },
            "id": request.get("id"),
        }
    current = _broker().get_current()
    instance_id = (current or {}).get("instance_id") if current and not current.get("error") else None
    response = _broker().send_request(request, instance_id)
    if response is None:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "IDA 请求超时"},
            "id": request.get("id"),
        }
    return response


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """代理 dispatch，路由请求到 IDA 或本地处理"""
    if not isinstance(request, dict):
        request = json.loads(request)
    
    method = request.get("method", "")
    
    # 本地协议方法
    if method in {"initialize", "ping"} or method.startswith("notifications/"):
        return dispatch_original(request)
    
    # tools/call - 判断是否 IDA 工具
    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name", "") if isinstance(params, dict) else ""
        
        if tool_name in IDA_TOOLS:
            return route_to_ida(request)
        
        return dispatch_original(request)
    
    # tools/list - 返回所有工具
    if method == "tools/list":
        response = dispatch_original(request)
        tools = response.get("result", {}).get("tools", []) if response else []
        current = _broker().get_current()
        if current and not current.get("error"):
            print(f"[MCP] tools/list: {len(tools)} 个工具 (IDA: {current.get('name', '')})", file=sys.stderr)
        else:
            print(f"[MCP] tools/list: {len(tools)} 个工具 (等待 IDA 连接)", file=sys.stderr)
        return response
    
    # resources 相关
    if method == "resources/list":
        return dispatch_original(request)
    if method == "resources/templates/list":
        return dispatch_original(request)
    if method == "resources/read":
        if not _broker().has_instances():
            return {"jsonrpc": "2.0", "result": {"contents": []}, "id": request.get("id")}
        return route_to_ida(request)
    
    # prompts 相关
    if method in {"prompts/list", "prompts/get"}:
        return dispatch_original(request)
    
    # 其他请求转发到 IDA
    return route_to_ida(request)


mcp.registry.dispatch = dispatch_proxy


# =====================================================================
def main():
    global HTTP_SERVER, _stdio_stdout, _broker_client

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="安装 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--uninstall", action="store_true", help="卸载 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--allow-ida-free", action="store_true", help="允许安装到 IDA Free")
    parser.add_argument("--config", action="store_true", help="打印 MCP 配置")
    parser.add_argument("--unsafe", action="store_true", help="启用不安全工具（调试器相关）")
    parser.add_argument("--port", type=int, default=13337, help="HTTP 服务器端口（Broker 模式）")
    parser.add_argument("--broker", action="store_true", help="仅启动 Broker（HTTP），不启动 stdio；多窗口/多 IDA 时请先单独运行")
    parser.add_argument("--broker-url", type=str, default="http://127.0.0.1:13337", help="MCP 模式连接 Broker 的 URL")
    args = parser.parse_args()

    # 注册工具
    _register_ida_tools(enable_unsafe=args.unsafe)
    _register_ida_resources()

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    if args.broker:
        # Broker 模式：仅启动 HTTP，持有 REGISTRY，阻塞主线程
        HTTP_SERVER = IDAHttpServer(port=args.port)
        HTTP_SERVER.start()
        print("[MCP] Broker 已启动，按 Ctrl+C 停止", file=sys.stderr)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            if HTTP_SERVER:
                HTTP_SERVER.stop()
        return

    # MCP 模式：不启动 HTTP，通过 Broker 客户端请求
    _broker_client = BrokerClient(args.broker_url, timeout=10.0)

    try:
        _stdio_stdout = sys.stdout.buffer
        mcp.stdio()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("[MCP] 正在退出...", file=sys.stderr)
        _stdio_stdout = None
        os._exit(0)


if __name__ == "__main__":
    main()
