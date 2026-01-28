"""IDA 实例管理 API - HTTP+SSE 版本

此模块提供 IDA 实例与 MCP 服务器的通信功能:
- 通过 HTTP 注册到 MCP 服务器
- 通过 SSE 接收 MCP 请求
- 自动重试连接

注意: 这些 API 仅在 IDA 端运行，用于与 MCP 服务器通信。
"""

import json
import threading
import time
import urllib.request
import urllib.error
from typing import Callable, Optional

# ============================================================================
# 配置
# ============================================================================

DEFAULT_SERVER_URL = "http://127.0.0.1:13337"

# 重连配置
RECONNECT_INTERVAL = 3.0  # 初始重连间隔（秒）
RECONNECT_MAX_INTERVAL = 30.0  # 最大重连间隔
RECONNECT_BACKOFF = 2.0  # 退避倍数


# ============================================================================
# 全局状态
# ============================================================================

_server_url: str = DEFAULT_SERVER_URL
_client_id: Optional[str] = None
_instance_id: Optional[str] = None
_connected = False
_running = False

_sse_thread: Optional[threading.Thread] = None
_on_mcp_request: Optional[Callable[[dict], dict]] = None

_auto_reconnect = True
_reconnect_attempt = 0
_last_connect_params: Optional[dict] = None


# ============================================================================
# HTTP 工具函数
# ============================================================================

def _http_post(url: str, data: dict, timeout: float = 3.0, silent: bool = False) -> Optional[dict]:
    """发送 HTTP POST 请求
    
    Args:
        url: 请求 URL
        data: 请求数据
        timeout: 超时时间（秒），默认 3 秒
        silent: 是否静默模式（不打印错误）
    """
    try:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        if not silent:
            print(f"[MCP] HTTP POST 失败 {url}: {e}")
        return None


def _parse_sse_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """解析 SSE 行，返回 (field, value)"""
    if not line or line.startswith(":"):
        return None, None
    if ":" in line:
        field, value = line.split(":", 1)
        return field.strip(), value.strip()
    return line, ""


# ============================================================================
# 连接管理
# ============================================================================

def connect_to_server(
    instance_id: str,
    instance_type: str = "gui",
    name: str = "",
    binary_path: str = "",
    arch_info: Optional[dict] = None,
    on_mcp_request: Optional[Callable[[dict], dict]] = None,
    server_url: Optional[str] = None,
) -> bool:
    """连接到 MCP 服务器
    
    Args:
        instance_id: 实例唯一标识
        instance_type: 实例类型 (gui/headless)
        name: 显示名称
        binary_path: 当前打开的二进制文件路径
        arch_info: 架构信息
        on_mcp_request: MCP 请求处理回调
        server_url: MCP 服务器 URL
    
    Returns:
        是否连接成功
    """
    global _server_url, _client_id, _instance_id, _connected, _running
    global _sse_thread, _on_mcp_request, _last_connect_params, _reconnect_attempt
    
    # 保存连接参数用于重连
    _last_connect_params = {
        "instance_id": instance_id,
        "instance_type": instance_type,
        "name": name,
        "binary_path": binary_path,
        "arch_info": arch_info,
        "on_mcp_request": on_mcp_request,
        "server_url": server_url,
    }
    
    _on_mcp_request = on_mcp_request
    _server_url = server_url or DEFAULT_SERVER_URL
    
    # 如果已连接，先断开
    if _connected:
        _close_connection()
    
    # 发送注册请求
    register_data = {
        "instance_id": instance_id,
        "instance_type": instance_type,
        "name": name,
        "binary_path": binary_path,
        "arch_info": arch_info or {},
    }
    
    # 重试时静默
    silent = _reconnect_attempt > 0
    result = _http_post(f"{_server_url}/register", register_data, silent=silent)
    if not result or not result.get("success"):
        if not silent:
            print(f"[MCP] 连接失败，等待 Cursor 启动后自动重连...")
        _schedule_reconnect()
        return False
    
    _client_id = result.get("client_id")
    _instance_id = instance_id
    _connected = True
    _running = True
    _reconnect_attempt = 0
    
    # 启动 SSE 监听线程
    _sse_thread = threading.Thread(target=_sse_loop, daemon=True)
    _sse_thread.start()
    
    return True


def _sse_loop():
    """SSE 事件循环"""
    global _connected, _running
    
    url = f"{_server_url}/events?client_id={_client_id}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=None) as resp:
            event_type = None
            event_data = ""
            
            for line_bytes in resp:
                if not _running:
                    break
                
                line = line_bytes.decode("utf-8").rstrip("\r\n")
                
                if not line:
                    # 空行表示事件结束
                    if event_type and event_data:
                        _handle_sse_event(event_type, event_data)
                    event_type = None
                    event_data = ""
                    continue
                
                field, value = _parse_sse_line(line)
                if field == "event":
                    event_type = value
                elif field == "data":
                    event_data = value
    
    except Exception as e:
        if _running:
            print(f"[MCP] SSE 连接断开: {e}")
    
    finally:
        _connected = False
        if _running and _auto_reconnect:
            _schedule_reconnect()


def _handle_sse_event(event_type: str, event_data: str):
    """处理 SSE 事件"""
    try:
        data = json.loads(event_data)
    except json.JSONDecodeError:
        return
    
    if event_type == "request":
        request_id = data.get("request_id")
        request = data.get("request")
        
        if request_id and request and _on_mcp_request:
            try:
                response = _on_mcp_request(request)
                _send_response(request_id, response)
            except Exception as e:
                _send_response(request_id, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": str(e)},
                    "id": request.get("id"),
                })
    
    elif event_type == "ping":
        pass  # 心跳，不需要处理
    
    elif event_type == "connected":
        print(f"[MCP] SSE 连接成功")


def _send_response(request_id: str, response: dict):
    """发送响应到服务器"""
    data = {
        "client_id": _client_id,
        "request_id": request_id,
        "response": response,
    }
    _http_post(f"{_server_url}/response", data)


# ============================================================================
# 自动重连
# ============================================================================

def _schedule_reconnect():
    """计划重连"""
    global _reconnect_attempt
    
    if not _auto_reconnect or not _last_connect_params:
        return
    
    # 指数退避
    interval = min(
        RECONNECT_INTERVAL * (RECONNECT_BACKOFF ** _reconnect_attempt),
        RECONNECT_MAX_INTERVAL
    )
    _reconnect_attempt += 1
    
    # 只在首次打印提示，后续静默重试
    # （首次提示已在 connect_to_server 中打印）
    
    timer = threading.Timer(interval, _try_reconnect)
    timer.daemon = True
    timer.start()


def _try_reconnect():
    """尝试重连"""
    if _connected or not _last_connect_params:
        return
    
    params = _last_connect_params
    success = connect_to_server(
        instance_id=params["instance_id"],
        instance_type=params["instance_type"],
        name=params["name"],
        binary_path=params["binary_path"],
        arch_info=params.get("arch_info"),
        on_mcp_request=params["on_mcp_request"],
        server_url=params["server_url"],
    )
    
    if success:
        print(f"[MCP] 重连成功 ({params['name']})")


def set_auto_reconnect(enabled: bool):
    """设置是否自动重连"""
    global _auto_reconnect
    _auto_reconnect = enabled


def _close_connection():
    """关闭连接"""
    global _connected, _running
    _running = False
    _connected = False


def _notify_server_disconnect():
    """通知服务端断开连接（实时断开检测）"""
    if _client_id:
        try:
            _http_post(f"{_server_url}/unregister", {"client_id": _client_id}, timeout=2.0)
        except Exception:
            pass  # 服务器可能已关闭，忽略错误


def disconnect():
    """断开连接（手动断开，不自动重连）"""
    global _auto_reconnect
    _auto_reconnect = False
    _notify_server_disconnect()  # 主动通知服务端
    _close_connection()


def is_connected() -> bool:
    """检查是否已连接"""
    return _connected


def get_instance_id() -> Optional[str]:
    """获取当前实例 ID"""
    return _instance_id
