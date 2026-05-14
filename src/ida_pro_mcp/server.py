"""IDA Pro MCP Server

  --broker: 单端口 HTTP 服务器 (0.0.0.0)，同时提供 MCP 端点和 IDA 注册端点
            远程 Cursor --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
  default:  本地 stdio 模式，通过 HTTP 转发到 Broker
"""

import argparse
import json
import os
import sys
import threading
from typing import BinaryIO, Optional


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(SCRIPT_DIR))
    from ida_pro_mcp.broker.manager import (
        get_broker_client,
        register_broker_tools,
        setup_dispatch_proxy,
    )
    from ida_pro_mcp.install import (
        install_ida_plugin,
        install_mcp_servers,
        print_mcp_config,
    )
    from ida_pro_mcp.tool_registry import (
        ToolDef,
        parse_all_api_files,
        tool_to_mcp_schema,
    )
else:
    from .broker.manager import (
        get_broker_client,
        register_broker_tools,
        setup_dispatch_proxy,
    )
    from .install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from .tool_registry import ToolDef, parse_all_api_files, tool_to_mcp_schema


sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer

sys.path.pop(0)


_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: Optional[dict] = None):
    """Send an MCP notification to the stdio client."""
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


mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# Register broker-local instance management tools.
register_broker_tools(mcp)


_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)
_IDA_TOOL_SCHEMAS = {t.name: tool_to_mcp_schema(t) for t in _IDA_TOOLS}

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """Create a lightweight local wrapper so tools/list exposes IDA tool schemas."""
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
    """Register all IDA-side tools as broker-routed MCP tool placeholders."""
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
        print(
            f"[MCP] 注册了 {registered_count} 个 IDA 工具 "
            f"(跳过 {skipped_unsafe} 个 unsafe 工具)",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具", file=sys.stderr)


def _register_ida_resources():
    """Register IDA resources locally so tools/list/resources/list stay complete."""
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


setup_dispatch_proxy(mcp, dispatch_original, IDA_TOOLS, _IDA_TOOL_SCHEMAS)


def main():
    global _stdio_stdout

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="安装 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--uninstall", action="store_true", help="卸载 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--allow-ida-free", action="store_true", help="允许安装到 IDA Free")
    parser.add_argument("--config", action="store_true", help="打印 MCP 配置")
    parser.add_argument("--unsafe", action="store_true", help="启用不安全工具（调试器相关）")
    parser.add_argument("--port", type=int, default=13337, help="HTTP 服务器端口（Broker 模式）")
    parser.add_argument(
        "--broker",
        action="store_true",
        help="启动 Broker HTTP 服务器（0.0.0.0），同时提供 MCP 和 IDA 注册端点；省略则使用 stdio",
    )
    parser.add_argument(
        "--broker-url",
        type=str,
        default="http://127.0.0.1:13337",
        help="MCP 模式连接 Broker 的 URL",
    )
    args = parser.parse_args()

    _register_ida_tools(enable_unsafe=args.unsafe)
    _register_ida_resources()

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    if args.broker:
        from .broker.combined import CombinedRequestHandler

        get_broker_client(f"http://127.0.0.1:{args.port}")
        mcp.cors_allowed_origins = ["*"]
        print(f"[MCP] Broker 已启动: http://0.0.0.0:{args.port}/mcp", file=sys.stderr)
        mcp.serve("0.0.0.0", args.port, background=False, request_handler=CombinedRequestHandler)
        return

    get_broker_client(args.broker_url)

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
