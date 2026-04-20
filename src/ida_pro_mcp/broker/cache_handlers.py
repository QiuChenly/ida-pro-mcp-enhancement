"""IDA 插件进程的"客户端 MCP 接管层"

当 Broker 把 `tools/call` 请求转发到 IDA 后，这一层在 ida_mcp 正常
`MCP_SERVER.registry.dispatch` 之前做拦截：

- 如果目标工具在 `CACHE_TOOL_NAMES` 集合里，改由本模块直接读本地
  `.mcp.sqlite` 缓存并构造响应 (完全不占用 IDA 主线程)。
- 未就绪 / 数据库缺失时直接返回 JSON-RPC error，不 fallback。

所有签名都是严格类型化的，返回 `JsonRpcResponse`。
"""

from __future__ import annotations

import json
from typing import Any, Mapping, cast

from . import sqlite_cache as _cache
from . import sqlite_query as _query
from .cache_types import (
    CacheStatusArgs,
    CacheStatusResult,
    EntityKind,
    EntityQueryArgs,
    EntityQueryResult,
    FindRegexArgs,
    FindRegexResult,
    ImportsArgs,
    JsonRpcError,
    JsonRpcId,
    JsonRpcRequest,
    JsonRpcResponse,
    ListFuncsArgs,
    ListFuncsResult,
    ListGlobalsArgs,
    ListGlobalsResult,
    ListImportsResult,
    McpTextContent,
    McpToolCallResult,
    RefreshCacheArgs,
    RefreshCacheResult,
)


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CACHE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "find_regex",
        "entity_query",
        "list_funcs",
        "list_globals",
        "imports",
        "refresh_cache",
        "cache_status",
    }
)

_VALID_ENTITY_KINDS: frozenset[str] = frozenset(
    {"strings", "functions", "globals", "imports"}
)


# ---------------------------------------------------------------------------
# JSON-RPC 封装
# ---------------------------------------------------------------------------


def _wrap_ok(req_id: JsonRpcId, payload: Mapping[str, Any]) -> JsonRpcResponse:
    text_content: McpTextContent = {
        "type": "text",
        "text": json.dumps(payload, ensure_ascii=False, default=str),
    }
    result: McpToolCallResult = {"content": [text_content], "isError": False}
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def _wrap_err(req_id: JsonRpcId, code: int, message: str) -> JsonRpcResponse:
    err: JsonRpcError = {"code": code, "message": message}
    return {"jsonrpc": "2.0", "error": err, "id": req_id}


# ---------------------------------------------------------------------------
# 参数解析工具
# ---------------------------------------------------------------------------


def _get_args(req: JsonRpcRequest) -> dict[str, Any]:
    params = req.get("params")
    if not isinstance(params, dict):
        return {}
    args = params.get("arguments")
    return args if isinstance(args, dict) else {}


def _get_tool_name(req: JsonRpcRequest) -> str:
    params = req.get("params")
    if not isinstance(params, dict):
        return ""
    name = params.get("name", "")
    return name if isinstance(name, str) else ""


def _opt_str(args: Mapping[str, Any], key: str) -> str | None:
    v = args.get(key)
    return v if isinstance(v, str) and v else None


def _int_or(args: Mapping[str, Any], key: str, default: int) -> int:
    v = args.get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _bool_or(args: Mapping[str, Any], key: str, default: bool) -> bool:
    v = args.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.lower() in {"1", "true", "yes", "y", "on"}
    return default


# ---------------------------------------------------------------------------
# 各工具 handler (强类型)
# ---------------------------------------------------------------------------


def _do_find_regex(args: FindRegexArgs, db_path: str) -> FindRegexResult:
    return _query.find_regex(
        db_path,
        pattern=args["pattern"],
        limit=_int_or(args, "limit", 100),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_entity_query(args: EntityQueryArgs, db_path: str) -> EntityQueryResult:
    return _query.entity_query(
        db_path,
        kind=args["kind"],
        name_pattern=_opt_str(args, "name_pattern"),
        segment=_opt_str(args, "segment"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", True),
    )


def _do_list_funcs(args: ListFuncsArgs, db_path: str) -> ListFuncsResult:
    return _query.list_funcs(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
        include_xrefs=_bool_or(args, "include_xrefs", False),
    )


def _do_list_globals(args: ListGlobalsArgs, db_path: str) -> ListGlobalsResult:
    return _query.list_globals(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        limit=_int_or(args, "limit", 200),
        offset=_int_or(args, "offset", 0),
    )


def _do_imports(args: ImportsArgs, db_path: str) -> ListImportsResult:
    return _query.list_imports(
        db_path,
        name_pattern=_opt_str(args, "name_pattern"),
        module_pattern=_opt_str(args, "module_pattern"),
        limit=_int_or(args, "limit", 500),
        offset=_int_or(args, "offset", 0),
    )


def _do_refresh_cache(_args: RefreshCacheArgs, idb_path: str) -> RefreshCacheResult:
    triggered = _cache.request_refresh(idb_path) if idb_path else False
    return {"triggered": bool(triggered), "idb_path": idb_path}


def _do_cache_status(_args: CacheStatusArgs, db_path: str) -> CacheStatusResult:
    return _query.cache_status(db_path)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def handle_cache_tool_locally(req: JsonRpcRequest, idb_path: str) -> JsonRpcResponse:
    """在 IDA 插件进程内部，直接用 SQLite 响应缓存类工具。

    调用前请先用 `is_cache_tool()` / `CACHE_TOOL_NAMES` 判断。
    """
    req_id: JsonRpcId = req.get("id")
    tool_name = _get_tool_name(req)
    raw_args = _get_args(req)

    if not idb_path:
        return _wrap_err(
            req_id,
            -32000,
            "当前 IDA 实例未提供 idb_path，无法定位本地 SQLite 缓存。",
        )

    db_path = _query.get_cache_path_for_binary(idb_path)
    if not db_path:
        return _wrap_err(req_id, -32000, "无法根据 idb_path 推导缓存数据库路径。")

    try:
        if tool_name == "find_regex":
            pattern = raw_args.get("pattern") or raw_args.get("regex")
            if not isinstance(pattern, str) or not pattern:
                return _wrap_err(req_id, -32602, "find_regex 需要 pattern 参数 (str)。")
            fr_args: FindRegexArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
                "pattern": pattern,
            }
            if "limit" in raw_args:
                fr_args["limit"] = _int_or(raw_args, "limit", 100)
            if "offset" in raw_args:
                fr_args["offset"] = _int_or(raw_args, "offset", 0)
            if "include_xrefs" in raw_args:
                fr_args["include_xrefs"] = _bool_or(raw_args, "include_xrefs", True)
            return _wrap_ok(req_id, _do_find_regex(fr_args, db_path))

        if tool_name == "entity_query":
            kind_raw = raw_args.get("kind") or raw_args.get("type")
            if not isinstance(kind_raw, str) or kind_raw not in _VALID_ENTITY_KINDS:
                return _wrap_err(
                    req_id,
                    -32602,
                    "entity_query 需要 kind 参数 (strings/functions/globals/imports)。",
                )
            kind = cast(EntityKind, kind_raw)
            eq_args: EntityQueryArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
                "kind": kind,
            }
            name_pat = _opt_str(raw_args, "name_pattern") or _opt_str(raw_args, "pattern")
            if name_pat is not None:
                eq_args["name_pattern"] = name_pat
            seg = _opt_str(raw_args, "segment")
            if seg is not None:
                eq_args["segment"] = seg
            if "limit" in raw_args:
                eq_args["limit"] = _int_or(raw_args, "limit", 200)
            if "offset" in raw_args:
                eq_args["offset"] = _int_or(raw_args, "offset", 0)
            if "include_xrefs" in raw_args:
                eq_args["include_xrefs"] = _bool_or(raw_args, "include_xrefs", True)
            return _wrap_ok(req_id, _do_entity_query(eq_args, db_path))

        if tool_name == "list_funcs":
            lf_args: ListFuncsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _opt_str(raw_args, "name_pattern") or _opt_str(raw_args, "pattern")
            if name_pat is not None:
                lf_args["name_pattern"] = name_pat
            if "limit" in raw_args:
                lf_args["limit"] = _int_or(raw_args, "limit", 200)
            if "offset" in raw_args:
                lf_args["offset"] = _int_or(raw_args, "offset", 0)
            if "include_xrefs" in raw_args:
                lf_args["include_xrefs"] = _bool_or(raw_args, "include_xrefs", False)
            return _wrap_ok(req_id, _do_list_funcs(lf_args, db_path))

        if tool_name == "list_globals":
            lg_args: ListGlobalsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _opt_str(raw_args, "name_pattern") or _opt_str(raw_args, "pattern")
            if name_pat is not None:
                lg_args["name_pattern"] = name_pat
            if "limit" in raw_args:
                lg_args["limit"] = _int_or(raw_args, "limit", 200)
            if "offset" in raw_args:
                lg_args["offset"] = _int_or(raw_args, "offset", 0)
            return _wrap_ok(req_id, _do_list_globals(lg_args, db_path))

        if tool_name == "imports":
            im_args: ImportsArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            name_pat = _opt_str(raw_args, "name_pattern") or _opt_str(raw_args, "pattern")
            if name_pat is not None:
                im_args["name_pattern"] = name_pat
            mod_pat = _opt_str(raw_args, "module_pattern") or _opt_str(raw_args, "module")
            if mod_pat is not None:
                im_args["module_pattern"] = mod_pat
            if "limit" in raw_args:
                im_args["limit"] = _int_or(raw_args, "limit", 500)
            if "offset" in raw_args:
                im_args["offset"] = _int_or(raw_args, "offset", 0)
            return _wrap_ok(req_id, _do_imports(im_args, db_path))

        if tool_name == "refresh_cache":
            rc_args: RefreshCacheArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_refresh_cache(rc_args, idb_path))

        if tool_name == "cache_status":
            cs_args: CacheStatusArgs = {
                "instance_id": str(raw_args.get("instance_id", "")),
            }
            return _wrap_ok(req_id, _do_cache_status(cs_args, db_path))

    except _query.CacheNotReadyError as e:
        return _wrap_err(req_id, -32001, str(e))
    except Exception as e:  # noqa: BLE001
        return _wrap_err(req_id, -32603, f"SQLite 缓存查询失败: {e}")

    return _wrap_err(req_id, -32601, f"未知缓存工具: {tool_name!r}")


def is_cache_tool(req: JsonRpcRequest) -> bool:
    """请求是否命中缓存拦截名单。"""
    if req.get("method") != "tools/call":
        return False
    return _get_tool_name(req) in CACHE_TOOL_NAMES
