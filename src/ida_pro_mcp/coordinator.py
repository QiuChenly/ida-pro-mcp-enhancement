"""IDA Pro MCP 中央协调服务器

此模块实现多实例IDA协调功能:
- 管理多个IDA实例的注册和状态
- 为MCP客户端提供统一的入口
- 通过HTTP路由请求到目标IDA实例
- 提供多实例管理API

架构:
    MCP客户端 <-> 协调服务器 <-> HTTP <-> 多个IDA实例(各自有HTTP服务)
"""

import os
import sys
import json
import time
import threading
import argparse
import http.client
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime

# 复用现有的MCP实现
if True:  # 避免TYPE_CHECKING导致的导入问题
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
    sys.path.pop(0)


# ============================================================================
# 实例注册表
# ============================================================================

@dataclass
class IDAInstance:
    """表示一个注册的IDA实例"""
    instance_id: str
    instance_type: str  # "gui" 或 "headless"
    host: str
    port: int
    name: str = ""
    binary_path: str = ""
    registered_at: datetime = field(default_factory=datetime.now)
    last_heartbeat: datetime = field(default_factory=datetime.now)
    tools: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "type": self.instance_type,
            "host": self.host,
            "port": self.port,
            "name": self.name or f"{self.instance_type}:{self.port}",
            "binary_path": self.binary_path,
            "registered_at": self.registered_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "url": f"http://{self.host}:{self.port}",
            "tools_count": len(self.tools),
        }
    
    def is_alive(self, timeout_sec: float = 90.0) -> bool:
        """检查实例是否存活（最后心跳时间在超时范围内）"""
        elapsed = (datetime.now() - self.last_heartbeat).total_seconds()
        return elapsed < timeout_sec


class InstanceRegistry:
    """IDA实例注册表，管理所有已注册的实例"""
    
    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._current_instance_id: Optional[str] = None
        self._lock = threading.RLock()
    
    def register(
        self,
        instance_id: str,
        instance_type: str,
        host: str,
        port: int,
        name: str = "",
        binary_path: str = "",
        tools: list[dict] | None = None,
    ) -> IDAInstance:
        """注册一个新的IDA实例"""
        with self._lock:
            instance = IDAInstance(
                instance_id=instance_id,
                instance_type=instance_type,
                host=host,
                port=port,
                name=name,
                binary_path=binary_path,
                tools=tools or [],
            )
            self._instances[instance_id] = instance
            
            # 如果是第一个实例，自动设为当前实例
            if self._current_instance_id is None:
                self._current_instance_id = instance_id
            
            tools_count = len(instance.tools)
            print(f"[Coordinator] 实例已注册: {instance_id} ({instance_type}:{port}, {tools_count}个工具)")
            return instance
    
    def unregister(self, instance_id: str) -> bool:
        """注销一个IDA实例"""
        with self._lock:
            if instance_id not in self._instances:
                return False
            
            del self._instances[instance_id]
            
            # 如果注销的是当前实例，清除或切换到下一个
            if self._current_instance_id == instance_id:
                if self._instances:
                    self._current_instance_id = next(iter(self._instances))
                else:
                    self._current_instance_id = None
            
            print(f"[Coordinator] 实例已注销: {instance_id}")
            return True
    
    def heartbeat(self, instance_id: str) -> bool:
        """更新实例心跳时间"""
        with self._lock:
            if instance_id not in self._instances:
                return False
            self._instances[instance_id].last_heartbeat = datetime.now()
            return True
    
    def update_tools(self, instance_id: str, tools: list[dict]) -> bool:
        """更新实例的工具列表"""
        with self._lock:
            if instance_id not in self._instances:
                return False
            self._instances[instance_id].tools = tools
            print(f"[Coordinator] 实例 {instance_id} 更新工具列表: {len(tools)}个工具")
            return True
    
    def get_current_tools(self) -> list[dict]:
        """获取当前活动实例的工具列表"""
        with self._lock:
            if self._current_instance_id is None:
                return []
            instance = self._instances.get(self._current_instance_id)
            return instance.tools if instance else []
    
    def get_instance(self, instance_id: str) -> Optional[IDAInstance]:
        """获取指定实例"""
        with self._lock:
            return self._instances.get(instance_id)
    
    def get_current(self) -> Optional[IDAInstance]:
        """获取当前活动实例"""
        with self._lock:
            if self._current_instance_id is None:
                return None
            return self._instances.get(self._current_instance_id)
    
    def set_current(self, instance_id: str) -> bool:
        """设置当前活动实例"""
        with self._lock:
            if instance_id not in self._instances:
                return False
            self._current_instance_id = instance_id
            print(f"[Coordinator] 切换到实例: {instance_id}")
            return True
    
    def list_all(self) -> list[dict]:
        """列出所有实例"""
        with self._lock:
            return [
                {
                    **inst.to_dict(),
                    "is_current": inst.instance_id == self._current_instance_id,
                    "is_alive": inst.is_alive(),
                }
                for inst in self._instances.values()
            ]
    
    def cleanup_dead(self, timeout_sec: float = 90.0) -> list[str]:
        """清理超时的实例"""
        with self._lock:
            dead_ids = [
                iid for iid, inst in self._instances.items()
                if not inst.is_alive(timeout_sec)
            ]
            for iid in dead_ids:
                self.unregister(iid)
            return dead_ids


# 全局注册表实例
REGISTRY = InstanceRegistry()


# ============================================================================
# MCP协调服务器
# ============================================================================

class CoordinatorMcpServer:
    """MCP协调服务器，集成实例管理和请求路由"""
    
    def __init__(self, name: str = "ida-pro-mcp-coordinator"):
        self.name = name
        self.mcp = McpServer(name)
        self._setup_tools()
        
        # 替换dispatch以支持请求路由
        self._original_dispatch = self.mcp.registry.dispatch
        self.mcp.registry.dispatch = self._dispatch_proxy
    
    def _setup_tools(self):
        """注册协调器自身的MCP工具"""
        
        @self.mcp.tool
        def instance_list() -> list[dict]:
            """列出所有注册的IDA实例
            
            返回所有已注册IDA实例的列表，包含每个实例的详细信息：
            - instance_id: 实例唯一标识
            - type: 实例类型 (gui/headless)
            - host/port: 实例地址
            - is_current: 是否为当前活动实例
            - is_alive: 是否存活
            """
            return REGISTRY.list_all()
        
        @self.mcp.tool
        def instance_current() -> dict:
            """获取当前活动IDA实例的信息
            
            返回当前选中的IDA实例详情。所有MCP工具调用将路由到此实例。
            如果没有活动实例，返回错误信息。
            """
            instance = REGISTRY.get_current()
            if instance is None:
                return {"error": "没有活动的IDA实例。请启动IDA并加载MCP插件。"}
            return {
                **instance.to_dict(),
                "is_current": True,
                "is_alive": instance.is_alive(),
            }
        
        @self.mcp.tool
        def instance_switch(instance_id: str) -> dict:
            """切换到指定的IDA实例
            
            将当前活动实例切换到指定ID的实例。切换后，所有MCP工具调用
            将路由到新的活动实例。
            
            Args:
                instance_id: 目标实例的唯一标识符
            """
            if REGISTRY.set_current(instance_id):
                instance = REGISTRY.get_instance(instance_id)
                return {
                    "success": True,
                    "message": f"已切换到实例: {instance_id}",
                    "instance": instance.to_dict() if instance else None,
                }
            return {
                "success": False,
                "error": f"实例不存在: {instance_id}",
            }
        
        @self.mcp.tool
        def instance_info(instance_id: str) -> dict:
            """获取指定IDA实例的详细信息
            
            Args:
                instance_id: 实例的唯一标识符
            """
            instance = REGISTRY.get_instance(instance_id)
            if instance is None:
                return {"error": f"实例不存在: {instance_id}"}
            return {
                **instance.to_dict(),
                "is_current": instance.instance_id == REGISTRY._current_instance_id,
                "is_alive": instance.is_alive(),
            }
    
    def _dispatch_proxy(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        """代理dispatch，将非本地工具请求路由到当前IDA实例"""
        request_obj: JsonRpcRequest = json.loads(request) if not isinstance(request, dict) else request  # type: ignore
        
        method = request_obj.get("method", "")
        
        # 协议方法（由协调器自己处理）
        local_methods = {
            "initialize", "ping",
            "prompts/list", "prompts/get",
            "notifications/cancelled",
        }
        local_tools = {
            "instance_list", "instance_current", "instance_switch", "instance_info"
        }
        
        # 处理tools/call，检查是否是本地工具
        if method == "tools/call":
            params = request_obj.get("params", {})
            tool_name = params.get("name", "") if isinstance(params, dict) else ""
            if tool_name in local_tools:
                return self._original_dispatch(request)
            # 非本地工具，路由到IDA实例
            return self._route_to_instance(request)
        
        # tools/list需要合并本地工具和远程工具
        if method == "tools/list":
            return self._merge_tools_list(request)
        
        # resources相关请求路由到IDA实例
        if method in {"resources/list", "resources/templates/list", "resources/read"}:
            return self._route_to_instance(request)
        
        # 其他协议方法由协调器处理
        if method in local_methods or method.startswith("notifications/"):
            return self._original_dispatch(request)
        
        # 其他请求路由到IDA实例
        return self._route_to_instance(request)
    
    def _route_to_instance(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        """将请求通过HTTP路由到当前活动的IDA实例"""
        instance = REGISTRY.get_current()
        
        if instance is None:
            request_obj = json.loads(request) if not isinstance(request, dict) else request
            request_id = request_obj.get("id")
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "没有活动的IDA实例。请启动IDA并加载MCP插件，或使用instance_list查看可用实例。",
                },
                "id": request_id,
            }
        
        # 通过HTTP转发请求到IDA实例
        try:
            conn = http.client.HTTPConnection(instance.host, instance.port, timeout=30)
            if isinstance(request, dict):
                request_bytes = json.dumps(request).encode("utf-8")
            elif isinstance(request, str):
                request_bytes = request.encode("utf-8")
            else:
                request_bytes = bytes(request)
            
            conn.request("POST", "/mcp", request_bytes, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        except Exception as e:
            request_obj = json.loads(request) if not isinstance(request, dict) else request
            request_id = request_obj.get("id")
            if request_id is None:
                return None
            
            full_info = traceback.format_exc()
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"连接IDA实例失败 ({instance.host}:{instance.port}): {e}\n{full_info}",
                },
                "id": request_id,
            }
        finally:
            conn.close()
    
    def _merge_tools_list(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        """合并本地工具和当前IDA实例的工具列表（使用缓存）"""
        # 获取本地工具（实例管理工具）
        local_response = self._original_dispatch(request)
        local_tools = local_response.get("result", {}).get("tools", []) if local_response else []
        
        # 获取当前实例的缓存工具列表
        remote_tools = REGISTRY.get_current_tools()
        
        # 合并工具列表
        request_obj = json.loads(request) if not isinstance(request, dict) else request
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": local_tools + remote_tools,
            },
            "id": request_obj.get("id"),
        }
    
    def serve(self, host: str, port: int, background: bool = False):
        """启动协调服务器"""
        self.mcp.serve(host, port, background=background)
    
    def stdio(self):
        """以stdio模式运行"""
        self.mcp.stdio()


# ============================================================================
# HTTP管理API
# ============================================================================

# 全局MCP服务器引用（用于HTTP处理）
_MCP_SERVER: Optional["CoordinatorMcpServer"] = None


class CoordinatorHttpHandler(BaseHTTPRequestHandler):
    """处理实例注册/心跳等内部HTTP API + MCP请求"""
    
    server_version = "ida-mcp-coordinator/1.0"
    
    def log_message(self, format, *args):
        pass  # 静默日志
    
    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        
        # MCP请求处理
        if path == "/mcp":
            self._handle_mcp(body)
            return
        
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return
        
        if path == "/api/register":
            self._handle_register(data)
        elif path == "/api/unregister":
            self._handle_unregister(data)
        elif path == "/api/heartbeat":
            self._handle_heartbeat(data)
        elif path == "/api/switch":
            self._handle_switch(data)
        elif path == "/api/update_tools":
            self._handle_update_tools(data)
        else:
            self._send_json(404, {"error": "Not found"})
    
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == "/api/instances":
            self._send_json(200, {"instances": REGISTRY.list_all()})
        elif path == "/api/current":
            instance = REGISTRY.get_current()
            if instance:
                self._send_json(200, instance.to_dict())
            else:
                self._send_json(200, {"error": "No active instance"})
        elif path == "/api/ping":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "Not found"})
    
    def _handle_mcp(self, body: bytes):
        """处理MCP JSON-RPC请求"""
        global _MCP_SERVER
        if _MCP_SERVER is None:
            self._send_json(503, {"error": "MCP server not initialized"})
            return
        
        try:
            response = _MCP_SERVER.mcp.registry.dispatch(body)
            if response is None:
                # Notification，无需响应
                self.send_response(204)
                self.end_headers()
            else:
                result_body = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(result_body)))
                self.end_headers()
                self.wfile.write(result_body)
        except Exception as e:
            self._send_json(500, {"error": str(e)})
    
    def _handle_register(self, data: dict):
        required = ["instance_id", "type", "port"]
        missing = [k for k in required if k not in data]
        if missing:
            self._send_json(400, {"error": f"Missing fields: {missing}"})
            return
        
        instance = REGISTRY.register(
            instance_id=data["instance_id"],
            instance_type=data["type"],
            host=data.get("host", "127.0.0.1"),
            port=data["port"],
            name=data.get("name", ""),
            binary_path=data.get("binary_path", ""),
            tools=data.get("tools", []),
        )
        self._send_json(200, {"success": True, "instance": instance.to_dict()})
    
    def _handle_unregister(self, data: dict):
        instance_id = data.get("instance_id")
        if not instance_id:
            self._send_json(400, {"error": "Missing instance_id"})
            return
        
        if REGISTRY.unregister(instance_id):
            self._send_json(200, {"success": True})
        else:
            self._send_json(404, {"error": "Instance not found"})
    
    def _handle_heartbeat(self, data: dict):
        instance_id = data.get("instance_id")
        if not instance_id:
            self._send_json(400, {"error": "Missing instance_id"})
            return
        
        if REGISTRY.heartbeat(instance_id):
            self._send_json(200, {"success": True})
        else:
            self._send_json(404, {"error": "Instance not found"})
    
    def _handle_switch(self, data: dict):
        instance_id = data.get("instance_id")
        if not instance_id:
            self._send_json(400, {"error": "Missing instance_id"})
            return
        
        if REGISTRY.set_current(instance_id):
            instance = REGISTRY.get_instance(instance_id)
            self._send_json(200, {
                "success": True,
                "instance": instance.to_dict() if instance else None,
            })
        else:
            self._send_json(404, {"error": f"Instance not found: {instance_id}"})
    
    def _handle_update_tools(self, data: dict):
        instance_id = data.get("instance_id")
        tools = data.get("tools")
        
        if not instance_id:
            self._send_json(400, {"error": "Missing instance_id"})
            return
        if tools is None:
            self._send_json(400, {"error": "Missing tools"})
            return
        
        if REGISTRY.update_tools(instance_id, tools):
            self._send_json(200, {"success": True, "tools_count": len(tools)})
        else:
            self._send_json(404, {"error": f"Instance not found: {instance_id}"})
    
    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ============================================================================
# 后台清理任务
# ============================================================================

def _cleanup_worker(interval: float = 30.0, timeout: float = 90.0):
    """后台线程，定期清理超时的实例"""
    while True:
        time.sleep(interval)
        dead = REGISTRY.cleanup_dead(timeout)
        if dead:
            print(f"[Coordinator] 已清理超时实例: {dead}")


# ============================================================================
# 主入口
# ============================================================================

def main():
    global _MCP_SERVER
    
    parser = argparse.ArgumentParser(description="IDA Pro MCP 协调服务器")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="监听地址 (默认: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8801,
        help="统一服务端口 (默认: 8801，同时处理管理API和MCP)",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "http"],
        help="MCP传输模式: stdio=Cursor客户端模式, http=独立HTTP服务 (默认: stdio)",
    )
    args = parser.parse_args()
    
    # 启动后台清理线程
    cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True)
    cleanup_thread.start()
    
    # 创建MCP服务器
    coordinator = CoordinatorMcpServer()
    _MCP_SERVER = coordinator
    
    # 启动统一HTTP服务器（管理API + MCP）
    http_server = ThreadingHTTPServer((args.host, args.port), CoordinatorHttpHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    print(f"[Coordinator] 服务启动: http://{args.host}:{args.port}")
    print(f"[Coordinator]   - 管理API: /api/instances, /api/register, /api/switch ...")
    print(f"[Coordinator]   - MCP端点: /mcp")
    
    try:
        if args.transport == "stdio":
            print(f"[Coordinator] MCP传输: stdio模式（等待Cursor客户端连接）")
            coordinator.stdio()
        else:
            print(f"[Coordinator] MCP传输: HTTP模式")
            print(f"[Coordinator] 按 Ctrl+C 停止服务...")
            import signal
            signal.pause()
    except KeyboardInterrupt:
        print("\n[Coordinator] 正在关闭...")
    finally:
        http_server.shutdown()


if __name__ == "__main__":
    main()
