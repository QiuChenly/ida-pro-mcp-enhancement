"""缓存模块协议类型 (TypedDict)

所有 Broker 端 / IDA 插件端共享的请求 / 响应协议类型集中放在这里。
Broker 进程只 import 本文件即可，不应 import `ida_pro_mcp.ida_mcp` 下任何
模块，以免触发 `idaapi` 等 IDA 专属依赖的加载。

本文件独立重声明了必要的 JSON-RPC TypedDict，避免通过
`ida_pro_mcp.ida_mcp.zeromcp.jsonrpc` 这条路径经过 `ida_mcp/__init__.py`
间接加载 IDA 模块。
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypeAlias, TypedDict


# ---------------------------------------------------------------------------
# JSON-RPC (与 ida_pro_mcp.ida_mcp.zeromcp.jsonrpc 协议兼容，独立声明)
# ---------------------------------------------------------------------------

JsonRpcId: TypeAlias = str | int | float | None
JsonRpcParams: TypeAlias = dict[str, Any] | list[Any] | None


class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[JsonRpcParams]
    id: NotRequired[JsonRpcId]


class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]


class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: JsonRpcId


# ---------------------------------------------------------------------------
# 通用 Literal / 枚举
# ---------------------------------------------------------------------------

EntityKind: TypeAlias = Literal["strings", "functions", "globals", "imports"]
XrefType: TypeAlias = Literal["code", "data"]
XrefDirection: TypeAlias = Literal["to", "from"]
CacheSource: TypeAlias = Literal["sqlite_cache"]
CacheRunStatus: TypeAlias = Literal["ready", "building", "missing"]


# ---------------------------------------------------------------------------
# 工具 Arguments  (传入 tools/call arguments.*)
# ---------------------------------------------------------------------------


class _BaseArgs(TypedDict):
    instance_id: str


class FindRegexArgs(_BaseArgs):
    pattern: str
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class EntityQueryArgs(_BaseArgs):
    kind: EntityKind
    name_pattern: NotRequired[str]
    segment: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class ListFuncsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class ListGlobalsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]


class ImportsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    module_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]


class RefreshCacheArgs(_BaseArgs):
    pass


class CacheStatusArgs(_BaseArgs):
    pass


# ---------------------------------------------------------------------------
# Xref / Item 结构
# ---------------------------------------------------------------------------


class XrefItem(TypedDict):
    addr: str
    type: XrefType


class StringItem(TypedDict):
    addr: str
    text: str
    length: int
    segment: str
    xrefs: NotRequired[list[XrefItem]]


class FunctionItem(TypedDict):
    addr: str
    name: str
    size: int
    segment: str
    has_type: bool
    xrefs_to: NotRequired[list[XrefItem]]


class GlobalItem(TypedDict):
    addr: str
    name: str
    size: int
    segment: str


class ImportItem(TypedDict):
    addr: str
    name: str
    module: str


EntityItem: TypeAlias = StringItem | FunctionItem | GlobalItem | ImportItem


# ---------------------------------------------------------------------------
# 工具返回值
# ---------------------------------------------------------------------------


class _PagedMeta(TypedDict):
    total: int
    offset: int
    limit: int
    source: CacheSource


class FindRegexResult(_PagedMeta):
    items: list[StringItem]


class EntityQueryResult(_PagedMeta):
    kind: EntityKind
    items: list[EntityItem]


class ListFuncsResult(_PagedMeta):
    items: list[FunctionItem]


class ListGlobalsResult(_PagedMeta):
    items: list[GlobalItem]


class ListImportsResult(_PagedMeta):
    items: list[ImportItem]


class RefreshCacheResult(TypedDict):
    triggered: bool
    idb_path: str


class CacheStatusResult(TypedDict):
    exists: bool
    db_path: str
    status: str
    meta: dict[str, str]
    strings: int
    string_xrefs: int
    functions: int
    function_xrefs: int
    globals: int
    imports: int


# ---------------------------------------------------------------------------
# MCP 协议壳：tools/call 的 result 外形
# ---------------------------------------------------------------------------


class McpTextContent(TypedDict):
    type: Literal["text"]
    text: str


class McpToolCallResult(TypedDict):
    content: list[McpTextContent]
    isError: bool


# ---------------------------------------------------------------------------
# tools/list schema 外形
# ---------------------------------------------------------------------------


class ToolInputSchema(TypedDict):
    type: Literal["object"]
    properties: dict[str, dict[str, Any]]
    required: list[str]


class ToolSchema(TypedDict):
    name: str
    description: str
    inputSchema: ToolInputSchema
