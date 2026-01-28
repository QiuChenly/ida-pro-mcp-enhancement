"""Broker HTTP 客户端

MCP 进程通过此模块请求 Broker（实例列表、当前实例、转发 IDA 请求）。
"""

import json
import urllib.error
import urllib.request
from typing import Any, Optional


class BrokerClient:
    """Broker HTTP 客户端"""

    def __init__(self, base_url: str = "http://127.0.0.1:13337", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        timeout = timeout if timeout is not None else self.timeout
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"} if body else {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
            print(f"[MCP] Broker 请求失败 {path}: {e}", file=__import__("sys").stderr)
            return None

    def list_instances(self) -> list[dict]:
        """GET /api/instances"""
        out = self._request("GET", "/api/instances")
        return out if isinstance(out, list) else []

    def get_current(self) -> Optional[dict]:
        """GET /api/current"""
        return self._request("GET", "/api/current")

    def set_current(self, instance_id: str) -> dict:
        """POST /api/current"""
        out = self._request("POST", "/api/current", {"instance_id": instance_id})
        return out if isinstance(out, dict) else {"success": False, "error": "Broker 无响应"}

    def send_request(
        self,
        request: dict,
        instance_id: Optional[str] = None,
        timeout: float = 60.0,
    ) -> Optional[dict]:
        """POST /api/request，返回 IDA 响应"""
        payload = {"request": request, "timeout": timeout}
        if instance_id is not None:
            payload["instance_id"] = instance_id
        out = self._request("POST", "/api/request", payload, timeout=timeout + 5)
        if out is None:
            return None
        return out.get("response")

    def has_instances(self) -> bool:
        """是否有已连接实例"""
        return len(self.list_instances()) > 0
