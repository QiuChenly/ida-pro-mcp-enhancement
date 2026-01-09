"""IDA实例管理API - 多实例架构支持

此模块提供IDA实例注册和状态上报功能:
- 自动向协调服务器注册
- 心跳机制保持连接
- 工具列表导出

注意: 这些API仅在IDA端运行，用于与协调服务器通信。
"""

import json
import threading
import http.client
from typing import Optional


# ============================================================================
# 协调服务器连接配置（固定本地端口）
# ============================================================================

COORDINATOR_HOST = "127.0.0.1"
COORDINATOR_PORT = 8801

# 心跳间隔（秒）
HEARTBEAT_INTERVAL = 30.0

# 全局状态
_instance_id: Optional[str] = None
_heartbeat_thread: Optional[threading.Thread] = None
_heartbeat_stop_event = threading.Event()


# ============================================================================
# 内部函数
# ============================================================================

def _make_api_request(method: str, path: str, data: dict | None = None) -> dict:
    """向协调服务器发送API请求"""
    try:
        conn = http.client.HTTPConnection(COORDINATOR_HOST, COORDINATOR_PORT, timeout=5)
        body = json.dumps(data).encode("utf-8") if data else b""
        headers = {"Content-Type": "application/json"} if data else {}
        
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        result = json.loads(response.read().decode())
        conn.close()
        return result
    except Exception as e:
        return {"error": str(e), "coordinator_url": f"{COORDINATOR_HOST}:{COORDINATOR_PORT}"}


_heartbeat_failed_once = False


def _heartbeat_worker():
    """心跳工作线程"""
    global _instance_id, _heartbeat_failed_once
    
    while not _heartbeat_stop_event.wait(HEARTBEAT_INTERVAL):
        if _instance_id:
            result = _make_api_request("POST", "/api/heartbeat", {"instance_id": _instance_id})
            if "error" in result:
                if not _heartbeat_failed_once:
                    print(f"[MCP] 心跳失败: {result.get('error')} (后续失败不再提示)")
                    _heartbeat_failed_once = True
            else:
                _heartbeat_failed_once = False  # 恢复成功，重置


def _start_heartbeat():
    """启动心跳线程"""
    global _heartbeat_thread
    
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        return
    
    _heartbeat_stop_event.clear()
    _heartbeat_thread = threading.Thread(target=_heartbeat_worker, daemon=True)
    _heartbeat_thread.start()


def _stop_heartbeat():
    """停止心跳线程"""
    _heartbeat_stop_event.set()


# ============================================================================
# 注册与注销功能
# ============================================================================

def register_to_coordinator(
    instance_id: str,
    instance_type: str,
    port: int,
    host: str = "127.0.0.1",
    name: str = "",
    binary_path: str = "",
    tools: list[dict] | None = None,
) -> dict:
    """向协调服务器注册此IDA实例
    
    Args:
        instance_id: 实例唯一标识符
        instance_type: 实例类型 ("gui" 或 "headless")
        port: MCP服务端口
        host: 主机地址
        name: 可选的显示名称
        binary_path: 当前打开的二进制文件路径
        tools: 可选的MCP工具列表
    
    Returns:
        注册结果字典
    """
    global _instance_id
    
    result = _make_api_request("POST", "/api/register", {
        "instance_id": instance_id,
        "type": instance_type,
        "host": host,
        "port": port,
        "name": name,
        "binary_path": binary_path,
        "tools": tools or [],
    })
    
    if result.get("success"):
        _instance_id = instance_id
        _start_heartbeat()
        tools_count = len(tools) if tools else 0
        print(f"[MCP] 已注册到协调服务器: {instance_id} ({tools_count}个工具)")
    
    return result


def unregister_from_coordinator() -> dict:
    """从协调服务器注销此IDA实例"""
    global _instance_id, _heartbeat_failed_once
    
    if _instance_id is None:
        return {"success": True}
    
    _stop_heartbeat()
    
    old_id = _instance_id
    _instance_id = None  # 先清除，无论注销是否成功都释放本地状态
    _heartbeat_failed_once = False  # 重置心跳失败标记
    
    result = _make_api_request("POST", "/api/unregister", {"instance_id": old_id})
    
    if result.get("success"):
        print(f"[MCP] 已从协调服务器注销: {old_id}")
    
    return result


def get_local_tools_list() -> list[dict]:
    """获取本地MCP服务器的工具列表
    
    Returns:
        工具列表
    """
    from . import MCP_SERVER
    # 调用 _mcp_tools_list 获取工具列表
    result = MCP_SERVER._mcp_tools_list()
    return result.get("tools", [])


def get_registered_instance_id() -> Optional[str]:
    """获取当前注册的实例ID"""
    return _instance_id
