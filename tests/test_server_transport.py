import copy
import unittest

from ida_pro_mcp import server
from ida_pro_mcp.broker import manager as broker_manager


class _FakeBrokerClient:
    def __init__(self, *, instances=None, response=None):
        self.instances = instances if instances is not None else []
        self.response = response
        self.sent: list[tuple[dict, str | None, float]] = []
        self.list_calls = 0

    def list_instances(self) -> list[dict]:
        self.list_calls += 1
        return list(self.instances)

    def has_instances(self) -> bool:
        return bool(self.instances)

    def send_request(
        self,
        request: dict,
        instance_id: str | None = None,
        timeout: float = 60.0,
    ) -> dict | None:
        self.sent.append((copy.deepcopy(request), instance_id, timeout))
        return self.response


class _PatchedBroker:
    def __init__(self, fake: _FakeBrokerClient):
        self.fake = fake
        self.old = None

    def __enter__(self) -> _FakeBrokerClient:
        self.old = broker_manager._broker_client
        broker_manager._broker_client = self.fake
        return self.fake

    def __exit__(self, *exc_info):
        broker_manager._broker_client = self.old


def _dispatch(request: dict) -> dict | None:
    return server.mcp.registry.dispatch(request)


class BrokerDispatchTransportTests(unittest.TestCase):
    def test_tools_call_without_instances_returns_broker_error(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "refresh_cache",
                "arguments": {"instance_id": "ida-1"},
            },
        }
        with _PatchedBroker(_FakeBrokerClient()) as fake:
            response = _dispatch(request)

        self.assertEqual(response["error"]["code"], -32000)
        self.assertIn("没有活动的 IDA 实例", response["error"]["message"])
        self.assertEqual(fake.sent, [])

    def test_tools_call_requires_explicit_instance_id(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "refresh_cache", "arguments": {}},
        }
        fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}])
        with _PatchedBroker(fake):
            response = _dispatch(request)

        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("必须提供 instance_id", response["error"]["message"])
        self.assertEqual(fake.sent, [])

    def test_tools_call_routes_once_and_strips_instance_id(self):
        upstream_response = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "refresh_cache",
                "arguments": {"instance_id": "ida-1", "force": True},
            },
        }
        fake = _FakeBrokerClient(
            instances=[{"instance_id": "ida-1"}],
            response=upstream_response,
        )
        with _PatchedBroker(fake):
            response = _dispatch(request)

        self.assertEqual(response, upstream_response)
        self.assertEqual(len(fake.sent), 1)
        forwarded_request, instance_id, timeout = fake.sent[0]
        self.assertEqual(instance_id, "ida-1")
        self.assertEqual(timeout, 60.0)
        self.assertEqual(
            forwarded_request["params"]["arguments"],
            {"force": True},
        )

    def test_tools_call_timeout_response_is_not_retried(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "cache_status",
                "arguments": {"instance_id": "ida-1"},
            },
        }
        fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}], response=None)
        with _PatchedBroker(fake):
            response = _dispatch(request)

        self.assertEqual(response["error"]["code"], -32000)
        self.assertIn("IDA 请求超时", response["error"]["message"])
        self.assertEqual(len(fake.sent), 1)

    def test_tools_list_includes_broker_and_virtual_cache_tools(self):
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        fake = _FakeBrokerClient(instances=[{"instance_id": "ida-1"}])
        with _PatchedBroker(fake):
            response = _dispatch(request)

        self.assertIn("result", response)
        tool_names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("instance_list", tool_names)
        self.assertIn("instance_info", tool_names)
        self.assertIn("refresh_cache", tool_names)
        self.assertIn("cache_status", tool_names)
        self.assertEqual(fake.list_calls, 1)

    def test_resources_read_without_instances_returns_empty_contents(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "ida://cursor"},
        }
        with _PatchedBroker(_FakeBrokerClient()) as fake:
            response = _dispatch(request)

        self.assertEqual(response["result"], {"contents": []})
        self.assertEqual(fake.sent, [])

    def test_resources_read_with_instance_routes_through_broker(self):
        upstream_response = {"jsonrpc": "2.0", "id": 1, "result": {"contents": []}}
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "ida://cursor"},
        }
        fake = _FakeBrokerClient(
            instances=[{"instance_id": "ida-1"}],
            response=upstream_response,
        )
        with _PatchedBroker(fake):
            response = _dispatch(request)

        self.assertEqual(response, upstream_response)
        self.assertEqual(len(fake.sent), 1)
        _, instance_id, _ = fake.sent[0]
        self.assertIsNone(instance_id)


if __name__ == "__main__":
    unittest.main()
