"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

支持多实例模式:
- 启动本地HTTP服务器
- 自动尝试向协调服务器 (127.0.0.1:8801) 注册
- 关闭时自动注销
"""

import os
import sys
import socket
import http.client
import json
import idaapi
import idc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


# 协调服务器配置
COORDINATOR_HOST = "127.0.0.1"
COORDINATOR_PORT = 8801


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def _generate_instance_id(port: int) -> str:
    """生成实例ID，基于端口和进程ID"""
    return f"ida-{port}-{os.getpid()}"


def _get_current_binary_path() -> str:
    """获取当前打开的二进制文件路径"""
    try:
        return idc.get_input_file_path() or ""
    except Exception:
        return ""


def _check_coordinator_online() -> bool:
    """检查协调服务器是否在线"""
    try:
        conn = http.client.HTTPConnection(COORDINATOR_HOST, COORDINATOR_PORT, timeout=2)
        conn.request("GET", "/api/ping")
        response = conn.getresponse()
        result = json.loads(response.read().decode())
        conn.close()
        return result.get("status") == "ok"
    except Exception:
        return False


def _find_available_port(start_port: int = 10000, end_port: int = 65535) -> int:
    """找到一个可用的端口"""
    for port in range(start_port, end_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("无法找到可用端口")


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # 配置
    HOST = "127.0.0.1"
    DEFAULT_PORT = 13337  # 默认端口（单实例模式使用）

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self._instance_id: str | None = None
        self._actual_port: int = self.DEFAULT_PORT
        self._coordinator_mode: bool = False
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            # 先注销再停止
            self._unregister_from_coordinator()
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import (
                MCP_SERVER,
                IdaMcpHttpRequestHandler,
                init_caches,
                register_to_coordinator,
                unregister_from_coordinator,
                get_local_tools_list,
            )
        else:
            from ida_mcp import (
                MCP_SERVER,
                IdaMcpHttpRequestHandler,
                init_caches,
                register_to_coordinator,
                unregister_from_coordinator,
                get_local_tools_list,
            )

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # 先检查协调服务器是否在线
        self._coordinator_mode = _check_coordinator_online()
        
        if self._coordinator_mode:
            # 协调服务器在线：动态分配端口
            print(f"[MCP] 检测到协调服务器在线，使用动态端口分配...")
            try:
                port = _find_available_port()
            except RuntimeError as e:
                print(f"[MCP] 错误: {e}")
                return
        else:
            # 协调服务器不在线：使用默认端口（兼容单实例模式）
            print(f"[MCP] 协调服务器离线，使用默认端口 {self.DEFAULT_PORT}")
            port = self.DEFAULT_PORT

        # 启动服务器
        max_attempts = 10 if not self._coordinator_mode else 1
        
        for attempt in range(max_attempts):
            try:
                MCP_SERVER.serve(
                    self.HOST, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"[MCP] Server started:")
                print(f"  Streamable HTTP: http://{self.HOST}:{port}/mcp")
                print(f"  SSE: http://{self.HOST}:{port}/sse")
                print(f"  Config: http://{self.HOST}:{port}/config.html")
                self.mcp = MCP_SERVER
                self._actual_port = port
                break
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    if attempt < max_attempts - 1:
                        port += 1
                        print(f"[MCP] Port {port - 1} in use, trying {port}...")
                    else:
                        print(f"[MCP] Error: Could not find available port after {max_attempts} attempts")
                        return
                else:
                    raise

        # 如果协调服务器在线，注册此实例
        if self.mcp and self._coordinator_mode:
            self._register_to_coordinator()

    def _register_to_coordinator(self):
        """向协调服务器注册此实例"""
        try:
            if TYPE_CHECKING:
                from .ida_mcp import register_to_coordinator, get_local_tools_list
            else:
                from ida_mcp import register_to_coordinator, get_local_tools_list

            self._instance_id = _generate_instance_id(self._actual_port)
            binary_path = _get_current_binary_path()
            
            # 获取本地工具列表
            tools = get_local_tools_list()

            result = register_to_coordinator(
                instance_id=self._instance_id,
                instance_type="gui",
                port=self._actual_port,
                host=self.HOST,
                name=os.path.basename(binary_path) if binary_path else f"IDA:{self._actual_port}",
                binary_path=binary_path,
                tools=tools,
            )

            if result.get("success"):
                print(f"[MCP] 多实例模式: 已注册到协调服务器 ({COORDINATOR_HOST}:{COORDINATOR_PORT})")
            else:
                self._instance_id = None
                print(f"[MCP] 注册失败: {result.get('error', '未知错误')}")
        except Exception as e:
            self._instance_id = None
            print(f"[MCP] 注册时出错: {e}")

    def _unregister_from_coordinator(self):
        """从协调服务器注销此实例"""
        if not self._instance_id:
            return

        try:
            if TYPE_CHECKING:
                from .ida_mcp import unregister_from_coordinator
            else:
                from ida_mcp import unregister_from_coordinator

            unregister_from_coordinator()
            self._instance_id = None
        except Exception as e:
            print(f"[MCP] 注销时出错: {e}")

    def term(self):
        if self.mcp:
            self._unregister_from_coordinator()
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
