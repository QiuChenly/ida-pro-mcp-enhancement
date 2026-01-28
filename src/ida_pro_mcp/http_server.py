"""IDA HTTP+SSE 服务器

监听 HTTP 端口，接收 IDA 插件连接。
使用 SSE 推送 MCP 请求到 IDA。
"""

import json
import queue
import socketserver
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse
import sys


@dataclass
class IDAInstance:
    """IDA 实例信息"""
    client_id: str
    instance_id: str
    instance_type: str = "gui"
    name: str = ""
    binary_path: str = ""
    arch_info: dict = field(default_factory=dict)
    connected_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        result = {
            "client_id": self.client_id,
            "instance_id": self.instance_id,
            "type": self.instance_type,
            "name": self.name,
            "binary_path": self.binary_path,
        }
        if self.arch_info:
            result["processor"] = self.arch_info.get("processor", "")
            result["bitness"] = self.arch_info.get("bitness", 0)
            result["endian"] = self.arch_info.get("endian", "")
            result["file_type"] = self.arch_info.get("file_type", "")
            result["base_addr"] = self.arch_info.get("base_addr", "")
        return result


class IDARegistry:
    """IDA 实例注册表"""
    
    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._current_client_id: Optional[str] = None
        self._lock = threading.RLock()
        
        # SSE 队列：client_id -> Queue
        self._sse_queues: dict[str, queue.Queue] = {}
        
        # 待响应请求：request_id -> {event, response}
        self._pending: dict[str, dict] = {}
        
        # 回调
        self._on_connect: Optional[Callable[[IDAInstance], None]] = None
        self._on_disconnect: Optional[Callable[[str], None]] = None
    
    def register(self, data: dict) -> Optional[IDAInstance]:
        """注册 IDA 实例。同一 instance_id 重复连接时替换旧连接，避免列表中重复。"""
        with self._lock:
            instance_id = data.get("instance_id", "")
            # 同 instance_id 已存在则先移除旧连接（重连或重复点击导致）
            for old_client_id, old_inst in list(self._instances.items()):
                if old_inst.instance_id == instance_id:
                    self._instances.pop(old_client_id, None)
                    self._sse_queues.pop(old_client_id, None)
                    if self._current_client_id == old_client_id:
                        self._current_client_id = None
                    print(f"[HTTP] 替换旧连接: {old_inst.name or instance_id} ({old_client_id})", file=sys.stderr)
                    sys.stderr.flush()
                    break

            client_id = str(uuid.uuid4())[:8]
            instance = IDAInstance(
                client_id=client_id,
                instance_id=instance_id or client_id,
                instance_type=data.get("instance_type", "gui"),
                name=data.get("name", ""),
                binary_path=data.get("binary_path", ""),
                arch_info=data.get("arch_info", {}),
            )
            self._instances[client_id] = instance
            self._sse_queues[client_id] = queue.Queue()

            if self._current_client_id is None:
                self._current_client_id = client_id

            print(f"[HTTP] +++ IDA 已连接: {instance.name or instance.instance_id} +++", file=sys.stderr)
            sys.stderr.flush()

            if self._on_connect:
                self._on_connect(instance)

            return instance
    
    def unregister(self, client_id: str):
        """注销 IDA 实例"""
        with self._lock:
            instance = self._instances.pop(client_id, None)
            self._sse_queues.pop(client_id, None)
            
            if instance:
                print(f"[HTTP] --- IDA 已断开: {instance.name or instance.instance_id} ---", file=sys.stderr)
                sys.stderr.flush()
                
                if self._on_disconnect:
                    self._on_disconnect(instance.instance_id)
            
            if self._current_client_id == client_id:
                self._current_client_id = next(iter(self._instances), None)
    
    def get_current(self) -> Optional[IDAInstance]:
        """获取当前实例"""
        with self._lock:
            if self._current_client_id:
                return self._instances.get(self._current_client_id)
            return None
    
    def get_by_client_id(self, client_id: str) -> Optional[IDAInstance]:
        """根据 client_id 获取实例"""
        with self._lock:
            return self._instances.get(client_id)
    
    def get_by_instance_id(self, instance_id: str) -> Optional[IDAInstance]:
        """根据 instance_id 获取实例"""
        with self._lock:
            for inst in self._instances.values():
                if inst.instance_id == instance_id:
                    return inst
            return None
    
    def set_current(self, instance_id: str) -> bool:
        """设置当前实例"""
        with self._lock:
            for client_id, inst in self._instances.items():
                if inst.instance_id == instance_id:
                    self._current_client_id = client_id
                    return True
            return False
    
    def list_all(self) -> list[dict]:
        """列出所有实例"""
        with self._lock:
            return [
                {**inst.to_dict(), "is_current": inst.client_id == self._current_client_id}
                for inst in self._instances.values()
            ]
    
    def has_instances(self) -> bool:
        """是否有实例"""
        with self._lock:
            return len(self._instances) > 0
    
    def send_request(self, request: dict, instance_id: Optional[str] = None, timeout: float = 60.0) -> Optional[dict]:
        """发送请求到 IDA 并等待响应"""
        with self._lock:
            # 确定目标实例
            if instance_id:
                inst = self.get_by_instance_id(instance_id)
            else:
                inst = self.get_current()
            
            if not inst:
                return None
            
            client_id = inst.client_id
            sse_queue = self._sse_queues.get(client_id)
            if not sse_queue:
                return None
            
            # 创建请求跟踪
            request_id = str(uuid.uuid4())[:8]
            event = threading.Event()
            self._pending[request_id] = {"event": event, "response": None}
        
        # 放入 SSE 队列
        sse_queue.put({"request_id": request_id, "request": request})
        
        # 等待响应
        if event.wait(timeout):
            with self._lock:
                result = self._pending.pop(request_id, {})
                return result.get("response")
        else:
            with self._lock:
                self._pending.pop(request_id, None)
            return None
    
    def set_response(self, request_id: str, response: dict):
        """设置请求响应"""
        with self._lock:
            if request_id in self._pending:
                self._pending[request_id]["response"] = response
                self._pending[request_id]["event"].set()
    
    def get_sse_queue(self, client_id: str) -> Optional[queue.Queue]:
        """获取 SSE 队列"""
        with self._lock:
            return self._sse_queues.get(client_id)


# 全局注册表
REGISTRY = IDARegistry()


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""
    
    def log_message(self, format, *args):
        """重定向日志到 stderr"""
        print(f"[HTTP] {args[0]}", file=sys.stderr)
        sys.stderr.flush()
    
    def _send_json(self, data: dict, status: int = 200):
        """发送 JSON 响应"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    
    def _read_json(self) -> Optional[dict]:
        """读取 JSON 请求体"""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            body = self.rfile.read(length)
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None
    
    def do_OPTIONS(self):
        """处理 CORS 预检"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_POST(self):
        """处理 POST 请求"""
        path = urlparse(self.path).path
        
        if path == "/register":
            self._handle_register()
        elif path == "/unregister":
            self._handle_unregister()
        elif path == "/response":
            self._handle_response()
        elif path == "/api/current":
            self._handle_api_current_set()
        elif path == "/api/request":
            self._handle_api_request()
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_GET(self):
        """处理 GET 请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        if path == "/events":
            client_id = params.get("client_id", [None])[0]
            if client_id:
                self._handle_sse(client_id)
            else:
                self._send_json({"error": "Missing client_id"}, 400)
        elif path == "/status":
            self._send_json({"instances": REGISTRY.list_all()})
        elif path == "/api/instances":
            self._send_json(REGISTRY.list_all())
        elif path == "/api/current":
            self._handle_api_current_get()
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def _handle_register(self):
        """处理 IDA 注册"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        instance = REGISTRY.register(data)
        if instance:
            self._send_json({"success": True, "client_id": instance.client_id})
        else:
            self._send_json({"error": "Registration failed"}, 500)
    
    def _handle_unregister(self):
        """处理 IDA 主动断开"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        client_id = data.get("client_id")
        if client_id:
            REGISTRY.unregister(client_id)
            self._send_json({"success": True})
        else:
            self._send_json({"error": "Missing client_id"}, 400)
    
    def _handle_response(self):
        """处理 IDA 响应"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        request_id = data.get("request_id")
        response = data.get("response")
        
        if request_id and response:
            REGISTRY.set_response(request_id, response)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Missing request_id or response"}, 400)
    
    def _handle_api_current_get(self):
        """GET /api/current - 返回当前实例信息（供 MCP 客户端调用）"""
        instance = REGISTRY.get_current()
        if instance is None:
            self._send_json({"error": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。"})
            return
        self._send_json({**instance.to_dict(), "is_current": True})
    
    def _handle_api_current_set(self):
        """POST /api/current - 设置当前实例（供 MCP 客户端调用）"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        instance_id = data.get("instance_id")
        if not instance_id:
            self._send_json({"success": False, "error": "Missing instance_id"}, 400)
            return
        if REGISTRY.set_current(instance_id):
            instance = REGISTRY.get_by_instance_id(instance_id)
            self._send_json({
                "success": True,
                "message": f"已切换到实例: {instance_id}",
                "instance": instance.to_dict() if instance else None,
            })
        else:
            self._send_json({"success": False, "error": f"实例不存在: {instance_id}"})
    
    def _handle_api_request(self):
        """POST /api/request - 转发 MCP 请求到 IDA 并返回响应（供 MCP 客户端调用）"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        request = data.get("request")
        instance_id = data.get("instance_id")
        timeout = float(data.get("timeout", 60.0))
        if not request:
            self._send_json({"error": "Missing request"}, 400)
            return
        if not REGISTRY.has_instances():
            self._send_json({
                "error": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。",
                "response": None,
            })
            return
        response = REGISTRY.send_request(request, instance_id, timeout=timeout)
        self._send_json({"response": response})
    
    def _handle_sse(self, client_id: str):
        """处理 SSE 连接"""
        instance = REGISTRY.get_by_client_id(client_id)
        if not instance:
            self._send_json({"error": "Unknown client_id"}, 404)
            return
        
        sse_queue = REGISTRY.get_sse_queue(client_id)
        if not sse_queue:
            self._send_json({"error": "No queue"}, 500)
            return
        
        # 发送 SSE 头
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        # 发送连接成功事件
        self._send_sse_event("connected", {"client_id": client_id})
        
        try:
            while True:
                try:
                    # 每 10 秒发送心跳检测连接状态
                    # 注意：心跳是单向的，只有 TCP 连接断开（进程退出）才会失败
                    # IDA 主线程卡住时 TCP 连接仍存在，不会误判为断开
                    item = sse_queue.get(timeout=10)
                    self._send_sse_event("request", item)
                except queue.Empty:
                    # 发送心跳，写入失败会触发 BrokenPipeError
                    self._send_sse_event("ping", {})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # 断开连接时注销
            REGISTRY.unregister(client_id)
    
    def _send_sse_event(self, event: str, data: dict):
        """发送 SSE 事件"""
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务器：每个请求（含长连接 SSE）在独立线程中处理，避免第二个 IDA 的 /register 被阻塞。"""
    daemon_threads = True


class IDAHttpServer:
    """IDA HTTP+SSE 服务器"""

    def __init__(self, port: int = 13337):
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """启动服务器"""
        if self._running:
            return

        try:
            self._server = ThreadedHTTPServer(("127.0.0.1", self.port), IDARequestHandler)
            self._server.timeout = 1
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

            print(f"[HTTP] 服务器已启动 (多线程): http://127.0.0.1:{self.port}", file=sys.stderr)
            sys.stderr.flush()
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[HTTP] 端口 {self.port} 已被占用，跳过 HTTP 服务器启动", file=sys.stderr)
                sys.stderr.flush()
            else:
                raise

    def _serve(self):
        """服务循环（每 accept 一个连接由 ThreadingMixIn 派发到新线程）"""
        while self._running:
            try:
                self._server.handle_request()
            except Exception:
                if self._running:
                    pass
    
    def stop(self):
        """停止服务器"""
        self._running = False
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None
    
    @property
    def registry(self) -> IDARegistry:
        """获取注册表"""
        return REGISTRY
