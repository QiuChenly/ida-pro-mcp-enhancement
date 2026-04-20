"""SQLite 缓存只读查询层（强类型）

所有公开函数直接返回 `broker.cache_types` 中声明的 TypedDict，
禁止返回弱类型字典或内部 dataclass。

IDA 插件进程在 `ida_mcp.py` 的拦截层中调用本模块；Broker 进程永远
不应 import 本模块。
"""

from __future__ import annotations

import os
import re
import sqlite3
from typing import Optional

from .cache_types import (
    CacheStatusResult,
    EntityItem,
    EntityKind,
    EntityQueryResult,
    FindRegexResult,
    FunctionItem,
    GlobalItem,
    ImportItem,
    ListFuncsResult,
    ListGlobalsResult,
    ListImportsResult,
    StringItem,
    XrefItem,
    XrefType,
)
from .sqlite_cache import resolve_cache_path


CACHE_STATUS_READY = "ready"
CACHE_STATUS_BUILDING = "building"


class CacheNotReadyError(RuntimeError):
    """缓存还没写好 / 数据库文件不存在 / status != ready。"""


# ---------------------------------------------------------------------------
# sqlite3 连接 / REGEXP 扩展
# ---------------------------------------------------------------------------


def _regexp(expr: str, item: Optional[str]) -> int:
    """SQLite 的 REGEXP 运算符实现 (大小写敏感，Python re)。"""
    if item is None:
        return 0
    try:
        return 1 if re.search(expr, item) else 0
    except re.error:
        return 0


def _open_readonly(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise CacheNotReadyError(
            f"IDA 本地 SQLite 缓存数据库尚未创建 ({db_path})，"
            f"请等待插件完成首次分析或调用 refresh_cache 后重试。"
        )
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp, deterministic=True)
    return conn


def _read_status(conn: sqlite3.Connection) -> str:
    cur = conn.execute("SELECT value FROM meta WHERE key='status'")
    row = cur.fetchone()
    return str(row[0]) if row else ""


def ensure_ready(db_path: str) -> sqlite3.Connection:
    """打开连接并确保 status=ready，否则抛 CacheNotReadyError。"""
    conn = _open_readonly(db_path)
    status = _read_status(conn)
    if status != CACHE_STATUS_READY:
        conn.close()
        raise CacheNotReadyError(
            f"IDA 本地 SQLite 缓存数据库正在初始化或仍在自动分析 (status={status!r})，"
            f"请大模型稍后重试，或调用 refresh_cache 手动触发一次刷新。"
        )
    return conn


def get_cache_path_for_binary(idb_path: Optional[str]) -> Optional[str]:
    """把 IDB 路径映射为缓存数据库路径。"""
    return resolve_cache_path(idb_path) if idb_path else None


# ---------------------------------------------------------------------------
# Row -> TypedDict 显式装配 (不用 dict(row) 弱兜底)
# ---------------------------------------------------------------------------


def _row_to_xref(row: sqlite3.Row) -> XrefItem:
    type_str = str(row["type"])
    xtype: XrefType = "code" if type_str == "code" else "data"
    return {"addr": str(row["xref_addr"]), "type": xtype}


def _xrefs_for_string(conn: sqlite3.Connection, addr: str) -> list[XrefItem]:
    cur = conn.execute(
        "SELECT xref_addr, type FROM string_xrefs WHERE str_addr=? ORDER BY xref_addr",
        (addr,),
    )
    return [_row_to_xref(r) for r in cur.fetchall()]


def _xrefs_for_function_to(conn: sqlite3.Connection, addr: str) -> list[XrefItem]:
    cur = conn.execute(
        "SELECT xref_addr, type FROM function_xrefs "
        "WHERE func_addr=? AND direction='to' ORDER BY xref_addr",
        (addr,),
    )
    return [_row_to_xref(r) for r in cur.fetchall()]


def _row_to_string_item(row: sqlite3.Row) -> StringItem:
    return {
        "addr": str(row["addr"]),
        "text": str(row["text"]),
        "length": int(row["length"]),
        "segment": str(row["segment"] or ""),
    }


def _row_to_function_item(row: sqlite3.Row) -> FunctionItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "size": int(row["size"]),
        "segment": str(row["segment"] or ""),
        "has_type": bool(row["has_type"]),
    }


def _row_to_global_item(row: sqlite3.Row) -> GlobalItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "size": int(row["size"] or 0),
        "segment": str(row["segment"] or ""),
    }


def _row_to_import_item(row: sqlite3.Row) -> ImportItem:
    return {
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "module": str(row["module"] or ""),
    }


def _count(conn: sqlite3.Connection, sql: str, params: tuple) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# 查询函数 (公开接口)
# ---------------------------------------------------------------------------


def find_regex(
    db_path: str,
    pattern: str,
    *,
    limit: int = 100,
    offset: int = 0,
    include_xrefs: bool = True,
) -> FindRegexResult:
    conn = ensure_ready(db_path)
    try:
        total = _count(
            conn, "SELECT COUNT(*) FROM strings WHERE text REGEXP ?", (pattern,)
        )
        cur = conn.execute(
            "SELECT addr, text, length, segment FROM strings "
            "WHERE text REGEXP ? ORDER BY ea LIMIT ? OFFSET ?",
            (pattern, int(limit), int(offset)),
        )
        items: list[StringItem] = []
        for row in cur.fetchall():
            item = _row_to_string_item(row)
            if include_xrefs:
                item["xrefs"] = _xrefs_for_string(conn, item["addr"])
            items.append(item)
        return {
            "items": items,
            "total": total,
            "offset": int(offset),
            "limit": int(limit),
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_funcs(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    include_xrefs: bool = False,
) -> ListFuncsResult:
    conn = ensure_ready(db_path)
    try:
        where = ""
        params: tuple = ()
        if name_pattern:
            where = " WHERE name REGEXP ?"
            params = (name_pattern,)

        total = _count(conn, f"SELECT COUNT(*) FROM functions{where}", params)
        cur = conn.execute(
            f"SELECT addr, name, size, segment, has_type FROM functions{where} "
            f"ORDER BY ea LIMIT ? OFFSET ?",
            params + (int(limit), int(offset)),
        )
        items: list[FunctionItem] = []
        for row in cur.fetchall():
            item = _row_to_function_item(row)
            if include_xrefs:
                item["xrefs_to"] = _xrefs_for_function_to(conn, item["addr"])
            items.append(item)
        return {
            "items": items,
            "total": total,
            "offset": int(offset),
            "limit": int(limit),
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_globals(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> ListGlobalsResult:
    conn = ensure_ready(db_path)
    try:
        where = ""
        params: tuple = ()
        if name_pattern:
            where = " WHERE name REGEXP ?"
            params = (name_pattern,)

        total = _count(conn, f"SELECT COUNT(*) FROM globals{where}", params)
        cur = conn.execute(
            f"SELECT addr, name, size, segment FROM globals{where} "
            f"ORDER BY ea LIMIT ? OFFSET ?",
            params + (int(limit), int(offset)),
        )
        items = [_row_to_global_item(r) for r in cur.fetchall()]
        return {
            "items": items,
            "total": total,
            "offset": int(offset),
            "limit": int(limit),
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def list_imports(
    db_path: str,
    *,
    name_pattern: Optional[str] = None,
    module_pattern: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> ListImportsResult:
    conn = ensure_ready(db_path)
    try:
        clauses: list[str] = []
        params_list: list[str] = []
        if name_pattern:
            clauses.append("name REGEXP ?")
            params_list.append(name_pattern)
        if module_pattern:
            clauses.append("module REGEXP ?")
            params_list.append(module_pattern)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params = tuple(params_list)

        total = _count(conn, f"SELECT COUNT(*) FROM imports{where}", params)
        cur = conn.execute(
            f"SELECT addr, name, module FROM imports{where} "
            f"ORDER BY ea LIMIT ? OFFSET ?",
            params + (int(limit), int(offset)),
        )
        items = [_row_to_import_item(r) for r in cur.fetchall()]
        return {
            "items": items,
            "total": total,
            "offset": int(offset),
            "limit": int(limit),
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


def entity_query(
    db_path: str,
    kind: EntityKind,
    *,
    name_pattern: Optional[str] = None,
    segment: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    include_xrefs: bool = True,
) -> EntityQueryResult:
    if kind == "strings":
        conn = ensure_ready(db_path)
        try:
            clauses: list[str] = []
            params_list: list[str] = []
            if name_pattern:
                clauses.append("text REGEXP ?")
                params_list.append(name_pattern)
            if segment:
                clauses.append("segment = ?")
                params_list.append(segment)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            params = tuple(params_list)
            total = _count(conn, f"SELECT COUNT(*) FROM strings{where}", params)
            cur = conn.execute(
                f"SELECT addr, text, length, segment FROM strings{where} "
                f"ORDER BY ea LIMIT ? OFFSET ?",
                params + (int(limit), int(offset)),
            )
            str_items: list[EntityItem] = []
            for row in cur.fetchall():
                item = _row_to_string_item(row)
                if include_xrefs:
                    item["xrefs"] = _xrefs_for_string(conn, item["addr"])
                str_items.append(item)
            return {
                "kind": "strings",
                "items": str_items,
                "total": total,
                "offset": int(offset),
                "limit": int(limit),
                "source": "sqlite_cache",
            }
        finally:
            conn.close()

    if kind == "functions":
        sub = list_funcs(
            db_path,
            name_pattern=name_pattern,
            limit=limit,
            offset=offset,
            include_xrefs=include_xrefs,
        )
        fn_items: list[EntityItem] = list(sub["items"])
        return {
            "kind": "functions",
            "items": fn_items,
            "total": sub["total"],
            "offset": sub["offset"],
            "limit": sub["limit"],
            "source": "sqlite_cache",
        }

    if kind == "globals":
        gsub = list_globals(
            db_path, name_pattern=name_pattern, limit=limit, offset=offset
        )
        g_items: list[EntityItem] = list(gsub["items"])
        return {
            "kind": "globals",
            "items": g_items,
            "total": gsub["total"],
            "offset": gsub["offset"],
            "limit": gsub["limit"],
            "source": "sqlite_cache",
        }

    if kind == "imports":
        isub = list_imports(db_path, name_pattern=name_pattern, limit=limit, offset=offset)
        i_items: list[EntityItem] = list(isub["items"])
        return {
            "kind": "imports",
            "items": i_items,
            "total": isub["total"],
            "offset": isub["offset"],
            "limit": isub["limit"],
            "source": "sqlite_cache",
        }

    raise ValueError(
        f"未知的 entity kind={kind!r}，支持: strings / functions / globals / imports"
    )


def cache_status(db_path: str) -> CacheStatusResult:
    """查询缓存元信息；文件不存在时 status='missing'，不会抛错。"""
    if not os.path.exists(db_path):
        return {
            "exists": False,
            "db_path": db_path,
            "status": "missing",
            "meta": {},
            "strings": 0,
            "string_xrefs": 0,
            "functions": 0,
            "function_xrefs": 0,
            "globals": 0,
            "imports": 0,
        }
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        meta_rows = conn.execute("SELECT key, value FROM meta").fetchall()
        meta = {str(r["key"]): str(r["value"]) for r in meta_rows}

        def _tbl_count(tbl: str) -> int:
            row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            return int(row[0]) if row else 0

        return {
            "exists": True,
            "db_path": db_path,
            "status": meta.get("status", ""),
            "meta": meta,
            "strings": _tbl_count("strings"),
            "string_xrefs": _tbl_count("string_xrefs"),
            "functions": _tbl_count("functions"),
            "function_xrefs": _tbl_count("function_xrefs"),
            "globals": _tbl_count("globals"),
            "imports": _tbl_count("imports"),
        }
    finally:
        conn.close()
