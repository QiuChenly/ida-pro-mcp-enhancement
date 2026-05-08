"""Tests for the top-level Broker-mode stdio server and unsafe tool gating."""

import contextlib
import copy
import os
import sys

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE

try:
    from ida_pro_mcp import server
    from ida_pro_mcp.broker import manager as broker_manager
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import server  # type: ignore
        from broker import manager as broker_manager  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeBrokerClient:
    def __init__(self, *, instances=None, response=None):
        self.instances = instances if instances is not None else []
        self.response = response
        self.sent = []
        self.list_calls = 0

    def list_instances(self):
        self.list_calls += 1
        return list(self.instances)

    def has_instances(self):
        return bool(self.instances)

    def send_request(self, request, instance_id=None, timeout=60.0):
        self.sent.append((copy.deepcopy(request), instance_id, timeout))
        return self.response


@contextlib.contextmanager
def _patched_broker(fake):
    old = broker_manager._broker_client
    broker_manager._broker_client = fake
    try:
        yield fake
    finally:
        broker_manager._broker_client = old


def _dispatch(request):
    return server.mcp.registry.dispatch(request)


@test()
def test_tools_call_without_instances_returns_broker_error():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "refresh_cache", "arguments": {"instance_id": "ida-1"}},
    }
    with _patched_broker(_FakeBrokerClient()) as fake:
        response = _dispatch(request)
    assert response["error"]["code"] == -32000
    assert "没有活动的 IDA 实例" in response["error"]["message"]
    assert fake.sent == []


@test()
def test_tools_call_requires_instance_id():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "cache_status", "arguments": {}},
    }
    fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}])
    with _patched_broker(fake):
        response = _dispatch(request)
    assert response["error"]["code"] == -32602
    assert "必须提供 instance_id" in response["error"]["message"]
    assert fake.sent == []


@test()
def test_tools_call_routes_once_and_strips_instance_id():
    upstream = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "refresh_cache",
            "arguments": {"instance_id": "ida-1", "force": True},
        },
    }
    fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}], response=upstream)
    with _patched_broker(fake):
        response = _dispatch(request)
    assert response == upstream
    assert len(fake.sent) == 1
    forwarded, instance_id, timeout = fake.sent[0]
    assert instance_id == "ida-1"
    assert timeout == 60.0
    assert forwarded["params"]["arguments"] == {"force": True}


@test()
def test_tools_call_timeout_is_not_retried():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "cache_status", "arguments": {"instance_id": "ida-1"}},
    }
    fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}], response=None)
    with _patched_broker(fake):
        response = _dispatch(request)
    assert response["error"]["code"] == -32000
    assert "IDA 请求超时" in response["error"]["message"]
    assert len(fake.sent) == 1


@test()
def test_tools_list_keeps_broker_tools_when_ida_unreachable():
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    fake = _FakeBrokerClient()
    with _patched_broker(fake):
        response = _dispatch(request)
    assert "result" in response, f"Expected successful tools/list response, got: {response}"
    tool_names = {tool["name"] for tool in response["result"].get("tools", [])}
    assert "instance_list" in tool_names
    assert "instance_info" in tool_names
    assert "refresh_cache" in tool_names
    assert "cache_status" in tool_names


@test()
def test_resources_read_without_instances_returns_empty_contents():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "ida://cursor"},
    }
    with _patched_broker(_FakeBrokerClient()) as fake:
        response = _dispatch(request)
    assert response["result"] == {"contents": []}
    assert fake.sent == []


@test()
def test_resources_read_with_instance_routes_through_broker():
    upstream = {"jsonrpc": "2.0", "id": 1, "result": {"contents": []}}
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "ida://cursor"},
    }
    fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}], response=upstream)
    with _patched_broker(fake):
        response = _dispatch(request)
    assert response == upstream
    assert len(fake.sent) == 1
    assert fake.sent[0][1] is None


# ---------------------------------------------------------------------------
# Unsafe tool gating (idalib registry-removal approach, mirrors idalib_server)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _saved_tools():
    """Save and restore the tools registry so removal tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_unsafe_tools_registered():
    """@unsafe decorator should populate MCP_UNSAFE with known tool names."""
    assert len(MCP_UNSAFE) > 0, "MCP_UNSAFE is empty — no tools marked @unsafe"
    assert "py_eval" in MCP_UNSAFE, "py_eval should be marked @unsafe"
    assert "py_exec_file" in MCP_UNSAFE, "py_exec_file should be marked @unsafe"


@test()
def test_unsafe_tools_present_by_default():
    """Unsafe tools should be in the registry by default (plugin behavior)."""
    tool_names = set(MCP_SERVER.tools.methods)
    for name in ("py_eval", "py_exec_file"):
        assert name in tool_names, f"{name} should be present by default"


@test()
def test_unsafe_tools_hidden_after_removal():
    """tools/list should exclude tools removed from the registry (idalib --unsafe behavior)."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_list()
        tool_names = {t["name"] for t in result.get("tools", [])}
        leaked = MCP_UNSAFE & tool_names
        assert not leaked, f"Removed unsafe tools still listed: {leaked}"


@test()
def test_unsafe_tool_call_rejected_after_removal():
    """tools/call for a removed tool should return an error."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_call("py_eval", {"code": "pass"})
        assert result.get("isError"), f"Expected error for removed tool, got: {result}"


@test()
def test_safe_tools_unaffected_by_unsafe_removal():
    """Non-unsafe tools should remain callable after unsafe removal."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        assert "decompile" not in MCP_UNSAFE, "decompile should not be unsafe"
        assert "decompile" in MCP_SERVER.tools.methods, "decompile should survive removal"
