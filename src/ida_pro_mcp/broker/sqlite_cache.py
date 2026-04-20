"""IDA 静态信息 SQLite 持久化缓存

设计目标:
- 在 IDA 插件进程中运行后台守护线程，空闲时全量提取 IDA 数据库中的静态信息
  (strings, functions, globals, imports 及其 xref) 持久化到 SQLite 数据库。
- 数据库文件与 IDB 文件同目录、同名，后缀附加 `.mcp.sqlite`，
  这样同一个 IDB 第二次打开可以"秒开" (不需要重新拉取一遍)。
- 对外 (broker/manager 拦截器) 只提供只读查询接口，不与 IDA 主线程竞争。

所有实现都放在 broker 层, 不侵入上游 ida_mcp 目录下的代码。
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

# ============================================================================
# SQLite 数据库 Schema
# ============================================================================

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS strings (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    text TEXT NOT NULL,
    length INTEGER NOT NULL,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_strings_text ON strings(text);
CREATE INDEX IF NOT EXISTS idx_strings_segment ON strings(segment);

CREATE TABLE IF NOT EXISTS string_xrefs (
    str_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (str_addr, xref_addr)
);
CREATE INDEX IF NOT EXISTS idx_string_xrefs_str ON string_xrefs(str_addr);

CREATE TABLE IF NOT EXISTS functions (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    segment TEXT,
    has_type INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_segment ON functions(segment);

CREATE TABLE IF NOT EXISTS function_xrefs (
    func_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    direction TEXT NOT NULL,  -- 'to' (caller ->) or 'from' (-> callee)
    type TEXT NOT NULL,
    PRIMARY KEY (func_addr, xref_addr, direction)
);
CREATE INDEX IF NOT EXISTS idx_function_xrefs_func ON function_xrefs(func_addr);

CREATE TABLE IF NOT EXISTS globals (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(name);
CREATE INDEX IF NOT EXISTS idx_globals_segment ON globals(segment);

CREATE TABLE IF NOT EXISTS imports (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    module TEXT
);
CREATE INDEX IF NOT EXISTS idx_imports_name ON imports(name);
CREATE INDEX IF NOT EXISTS idx_imports_module ON imports(module);
"""


# ============================================================================
# 辅助: 数据库路径解析
# ============================================================================


def resolve_cache_path(idb_path: str) -> Optional[str]:
    """根据 IDB 路径计算缓存数据库路径。

    规则: `xxx.i64` -> `xxx.i64.mcp.sqlite`
    这样数据库文件名和 IDB 同步，客户端下次打开同一 IDB 可秒级加载。
    """
    if not idb_path:
        return None
    return idb_path + ".mcp.sqlite"


# ============================================================================
# 数据库连接辅助
# ============================================================================


def _connect(db_path: str) -> sqlite3.Connection:
    """打开/创建数据库连接，启用 WAL + FK。

    WAL 模式允许单写多读，即使 IDA 正在写入缓存，broker 也能继续高速查询。
    """
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.executescript(SCHEMA_SQL)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    cur = conn.execute("SELECT value FROM meta WHERE key=?", (key,))
    row = cur.fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
        (key, str(value)),
    )


# ============================================================================
# IDA 端: 空闲探测 + 全量提取 + 批量写入
#
# 所有使用 idaapi / idautils / idc 的代码都必须在 IDA 主线程上调用。
# 我们把"探测空闲"和"提取数据"都封装成可被 execute_sync 调度的小函数。
# ============================================================================


@dataclass
class CacheStats:
    strings: int = 0
    string_xrefs: int = 0
    functions: int = 0
    function_xrefs: int = 0
    globals_: int = 0
    imports: int = 0
    elapsed_ms: float = 0.0


def _ida_is_idle() -> bool:
    """在主线程检查 IDA 是否处于 idle (auto_analysis_ready && hexrays_ready)."""
    try:
        import ida_auto
        import ida_hexrays

        auto_ok = bool(ida_auto.auto_is_ok())
        try:
            hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            hexrays_ok = False
        return auto_ok and hexrays_ok
    except Exception:
        return False


def _collect_all_data() -> dict:
    """在主线程收集五大类静态信息。耗时与 IDB 大小成正比。"""
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    def _segname(ea: int) -> str:
        seg = idaapi.getseg(ea)
        if not seg:
            return ""
        try:
            return idaapi.get_segm_name(seg) or ""
        except Exception:
            return ""

    out: dict = {
        "strings": [],
        "string_xrefs": [],
        "functions": [],
        "function_xrefs": [],
        "globals": [],
        "imports": [],
    }

    # Strings + string xrefs
    for s in idautils.Strings():
        if s is None:
            continue
        try:
            ea = int(s.ea)
            text = str(s)
            length = len(text)
            addr = hex(ea)
            out["strings"].append((addr, ea, text, length, _segname(ea)))
            for xref in idautils.XrefsTo(ea, 0):
                xaddr = hex(xref.frm)
                xtype = "code" if xref.iscode else "data"
                out["string_xrefs"].append((addr, xaddr, int(xref.frm), xtype))
        except Exception:
            continue

    # Functions + function xrefs (to + from)
    for fea in idautils.Functions():
        try:
            fn = idaapi.get_func(fea)
            if not fn:
                continue
            fn_addr = hex(fn.start_ea)
            fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            fn_size = fn.end_ea - fn.start_ea
            has_type = 1 if ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea) else 0
            out["functions"].append(
                (fn_addr, int(fn.start_ea), fn_name, int(fn_size), _segname(fn.start_ea), has_type)
            )
            # Xrefs to: callers
            for xref in idautils.XrefsTo(fn.start_ea, 0):
                xtype = "code" if xref.iscode else "data"
                out["function_xrefs"].append(
                    (fn_addr, hex(xref.frm), int(xref.frm), "to", xtype)
                )
        except Exception:
            continue

    # Globals (names that are not functions)
    for ea, name in idautils.Names():
        try:
            if name is None:
                continue
            if idaapi.get_func(ea):
                continue
            out["globals"].append(
                (hex(ea), int(ea), name, int(idc.get_item_size(ea) or 0), _segname(ea))
            )
        except Exception:
            continue

    # Imports
    try:
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i) or "<unnamed>"

            def _cb(ea, symbol, ordinal, acc=out["imports"], mod=module):
                if not symbol:
                    symbol = f"#{ordinal}"
                acc.append((hex(ea), int(ea), symbol, mod))
                return True

            ida_nalt.enum_import_names(i, _cb)
    except Exception:
        pass

    return out


def _write_data_to_db(db_path: str, data: dict) -> CacheStats:
    """批量事务写入。写入前清空所有业务表。"""
    stats = CacheStats()
    t0 = time.perf_counter()
    conn = _connect(db_path)
    try:
        with conn:
            set_meta(conn, "status", "building")
            set_meta(conn, "schema_version", str(SCHEMA_VERSION))

            conn.execute("DELETE FROM strings")
            conn.execute("DELETE FROM string_xrefs")
            conn.execute("DELETE FROM functions")
            conn.execute("DELETE FROM function_xrefs")
            conn.execute("DELETE FROM globals")
            conn.execute("DELETE FROM imports")

            conn.executemany(
                "INSERT OR REPLACE INTO strings(addr, ea, text, length, segment) VALUES(?,?,?,?,?)",
                data["strings"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO string_xrefs(str_addr, xref_addr, xref_ea, type) VALUES(?,?,?,?)",
                data["string_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO functions(addr, ea, name, size, segment, has_type) VALUES(?,?,?,?,?,?)",
                data["functions"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO function_xrefs(func_addr, xref_addr, xref_ea, direction, type) VALUES(?,?,?,?,?)",
                data["function_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO globals(addr, ea, name, size, segment) VALUES(?,?,?,?,?)",
                data["globals"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO imports(addr, ea, name, module) VALUES(?,?,?,?)",
                data["imports"],
            )

            set_meta(conn, "status", "ready")
            set_meta(conn, "last_updated", str(int(time.time())))

        stats.strings = len(data["strings"])
        stats.string_xrefs = len(data["string_xrefs"])
        stats.functions = len(data["functions"])
        stats.function_xrefs = len(data["function_xrefs"])
        stats.globals_ = len(data["globals"])
        stats.imports = len(data["imports"])
    finally:
        conn.close()
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return stats


# ============================================================================
# 后台守护线程
# ============================================================================


REFRESH_INTERVAL_SEC = 5 * 60  # 5 分钟
IDLE_POLL_SEC = 2.0  # 未就绪时的快速探测节奏


@dataclass
class _DaemonHandle:
    idb_path: str
    db_path: str
    thread: threading.Thread
    stop_event: threading.Event
    force_event: threading.Event
    last_stats: Optional[CacheStats] = None
    last_error: Optional[str] = None


_daemons: dict[str, _DaemonHandle] = {}
_daemons_lock = threading.Lock()


def _execute_in_ida_main(fn):
    """把函数派发到 IDA 主线程并同步拿回返回值。

    依赖 ida_kernwin.execute_sync(..., MFF_READ)。失败时返回 None。
    """
    import ida_kernwin

    box: list = [None]
    exc_box: list = [None]

    def runner():
        try:
            box[0] = fn()
        except Exception as e:  # noqa: BLE001
            exc_box[0] = e
        return 1

    ida_kernwin.execute_sync(runner, ida_kernwin.MFF_READ)
    if exc_box[0] is not None:
        raise exc_box[0]
    return box[0]


def _run_build_once(handle: _DaemonHandle) -> None:
    try:
        data = _execute_in_ida_main(_collect_all_data)
        if data is None:
            return
        stats = _write_data_to_db(handle.db_path, data)
        handle.last_stats = stats
        handle.last_error = None
        print(
            f"[MCP][cache] 写入完成 {handle.db_path}: "
            f"strings={stats.strings} ({stats.string_xrefs} xrefs), "
            f"functions={stats.functions} ({stats.function_xrefs} xrefs), "
            f"globals={stats.globals_}, imports={stats.imports}, "
            f"elapsed={stats.elapsed_ms:.0f}ms",
            file=sys.stderr,
        )
    except Exception as e:  # noqa: BLE001
        handle.last_error = str(e)
        print(f"[MCP][cache] 构建失败: {e}", file=sys.stderr)


def _daemon_loop(handle: _DaemonHandle) -> None:
    """守护线程主循环。

    算法:
    1. 一直 poll IDA idle 状态，就绪后执行一次全量构建。
    2. 然后按 5 分钟周期循环；每次周期到点仍会再次检查 idle 后才构建。
    3. force_event 允许外部 (refresh_cache 工具) 立即唤醒。
    """
    # 首次构建 - 等待 idle
    print(f"[MCP][cache] 守护线程启动，目标数据库: {handle.db_path}", file=sys.stderr)
    try:
        _ensure_meta_building(handle.db_path)
    except Exception as e:  # noqa: BLE001
        print(f"[MCP][cache] 初始化数据库失败: {e}", file=sys.stderr)
        return

    # 1. 等待 idle 后首次构建
    while not handle.stop_event.is_set():
        try:
            idle = _execute_in_ida_main(_ida_is_idle)
        except Exception:
            idle = False
        if idle:
            _run_build_once(handle)
            break
        handle.stop_event.wait(IDLE_POLL_SEC)

    # 2. 周期性 / 被动刷新
    while not handle.stop_event.is_set():
        triggered = handle.force_event.wait(REFRESH_INTERVAL_SEC)
        if handle.stop_event.is_set():
            break
        handle.force_event.clear()
        # 无论是定时触发还是主动 force 触发，都必须等 IDA 空闲
        while not handle.stop_event.is_set():
            try:
                idle = _execute_in_ida_main(_ida_is_idle)
            except Exception:
                idle = False
            if idle:
                _run_build_once(handle)
                break
            handle.stop_event.wait(IDLE_POLL_SEC)


def _ensure_meta_building(db_path: str) -> None:
    """首次打开/新建数据库时写入 status=building，用于外部拦截器判断。

    如果数据库已存在且 status 已经是 ready，则保留 ready。
    这就是"秒开"：同一 IDB 第二次打开时缓存文件已存在，Broker 拦截立即生效，
    后台守护线程只需要在 idle 后做一次覆盖刷新。
    """
    conn = _connect(db_path)
    try:
        cur = conn.execute("SELECT value FROM meta WHERE key='status'")
        row = cur.fetchone()
        if row is None:
            with conn:
                set_meta(conn, "status", "building")
                set_meta(conn, "schema_version", str(SCHEMA_VERSION))
    finally:
        conn.close()


def start_cache_daemon(idb_path: str) -> Optional[str]:
    """启动与指定 IDB 关联的 SQLite 缓存后台守护线程。

    返回最终使用的数据库路径 (可能为 None 如果 idb_path 为空)。
    重复调用幂等: 若同一 idb_path 的守护线程已在运行则返回已有路径。
    """
    db_path = resolve_cache_path(idb_path)
    if not db_path:
        return None

    with _daemons_lock:
        existing = _daemons.get(idb_path)
        if existing and existing.thread.is_alive():
            return existing.db_path

        stop_event = threading.Event()
        force_event = threading.Event()
        handle = _DaemonHandle(
            idb_path=idb_path,
            db_path=db_path,
            thread=None,  # type: ignore[arg-type]
            stop_event=stop_event,
            force_event=force_event,
        )
        thread = threading.Thread(
            target=_daemon_loop,
            args=(handle,),
            name=f"mcp-sqlite-cache:{os.path.basename(idb_path)}",
            daemon=True,
        )
        handle.thread = thread
        _daemons[idb_path] = handle
        thread.start()

    return db_path


def request_refresh(idb_path: str) -> bool:
    """唤醒指定 IDB 对应的守护线程立即进行一次刷新。"""
    with _daemons_lock:
        handle = _daemons.get(idb_path)
    if handle is None:
        return False
    handle.force_event.set()
    return True


def stop_cache_daemon(idb_path: str) -> None:
    """停止指定守护线程并清理状态。"""
    with _daemons_lock:
        handle = _daemons.pop(idb_path, None)
    if handle is None:
        return
    handle.stop_event.set()
    handle.force_event.set()  # 唤醒等待
