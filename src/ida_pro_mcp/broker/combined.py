"""单端口合并处理器：MCP 协议 + Broker IDA 注册端点。

此文件独立于 broker/server.py，避免在非 IDA 环境下触发 zeromcp -> ida_mcp -> idaapi 的导入链。
仅当 --broker 模式启动时才被 import。
"""

import json
import os
import queue
import sys
from typing import Optional
from urllib.parse import parse_qs, urlparse

# 绕过 ida_mcp/__init__.py（会 import idaapi），直接加载 zeromcp
_zeromcp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ida_mcp")
sys.path.insert(0, _zeromcp_dir)
from zeromcp import McpHttpRequestHandler  # noqa: E402

from .server import REGISTRY


class CombinedRequestHandler(McpHttpRequestHandler):
    """单端口合并处理器，同时提供 MCP 协议端点和 Broker IDA 注册端点。

    路径分配:
      MCP 协议:
        GET  /sse          -> MCP SSE 长连接
        POST /sse          -> MCP SSE 消息
        POST /mcp          -> MCP Streamable HTTP
      Broker 注册:
        POST /register     -> IDA 插件注册
        POST /unregister   -> IDA 插件主动断开
        POST /response     -> IDA 插件回写响应
        POST /api/request  -> MCP 请求转发到 IDA
        GET  /events       -> IDA 插件 SSE 长连接
        GET  /status       -> 实例列表
        GET  /api/instances -> 实例列表 (JSON)
    """

    _BROKER_POST_PATHS = {"/register", "/unregister", "/response", "/api/request"}

    def do_POST(self):
        path = urlparse(self.path).path
        if path in self._BROKER_POST_PATHS:
            self._dispatch_broker_post(path)
            return
        super().do_POST()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/events":
            self._handle_broker_sse(parse_qs(parsed.query))
            return
        if path in ("/status", "/api/instances"):
            payload = (
                REGISTRY.list_all()
                if path == "/api/instances"
                else {"instances": REGISTRY.list_all()}
            )
            self._broker_json(payload)
            return
        super().do_GET()

    # -- Broker helpers --

    def _broker_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _broker_read_json(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None

    def _dispatch_broker_post(self, path: str):
        data = self._broker_read_json()
        if data is None:
            self._broker_json({"error": "Invalid JSON"}, 400)
            return

        if path == "/register":
            instance = REGISTRY.register(data)
            if instance:
                self._broker_json({"success": True, "client_id": instance.client_id})
            else:
                self._broker_json({"error": "Registration failed"}, 500)

        elif path == "/unregister":
            client_id = data.get("client_id")
            if client_id:
                REGISTRY.unregister(client_id)
                self._broker_json({"success": True})
            else:
                self._broker_json({"error": "Missing client_id"}, 400)

        elif path == "/response":
            request_id = data.get("request_id")
            response = data.get("response")
            if request_id and response:
                REGISTRY.set_response(request_id, response)
                self._broker_json({"ok": True})
            else:
                self._broker_json({"error": "Missing request_id or response"}, 400)

        elif path == "/api/request":
            request = data.get("request")
            instance_id = data.get("instance_id")
            timeout = float(data.get("timeout", 60.0))
            if not request:
                self._broker_json({"error": "Missing request"}, 400)
                return
            if not REGISTRY.has_instances():
                self._broker_json(
                    {
                        "error": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。",
                        "response": None,
                    }
                )
                return
            response = REGISTRY.send_request(request, instance_id, timeout=timeout)
            self._broker_json({"response": response})

    def _handle_broker_sse(self, params: dict):
        """IDA 插件 SSE 长连接"""
        client_id = params.get("client_id", [None])[0]
        if not client_id:
            self._broker_json({"error": "Missing client_id"}, 400)
            return

        instance = REGISTRY.get_by_client_id(client_id)
        if not instance:
            self._broker_json({"error": "Unknown client_id"}, 404)
            return

        sse_queue = REGISTRY.get_sse_queue(client_id)
        if not sse_queue:
            self._broker_json({"error": "No queue"}, 500)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self._broker_sse_event("connected", {"client_id": client_id})

        try:
            while True:
                try:
                    item = sse_queue.get(timeout=10)
                    self._broker_sse_event("request", item)
                except queue.Empty:
                    self._broker_sse_event("ping", {})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            REGISTRY.unregister(client_id)

    def _broker_sse_event(self, event: str, data: dict):
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()
