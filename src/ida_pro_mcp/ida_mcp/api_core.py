"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated

import idaapi
import idautils
import ida_nalt

from .rpc import tool
from .sync import idasync

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")


from .utils import (
    Function,
    ConvertedNumber,
    Global,
    Import,
    Page,
    NumberConversion,
    ListQuery,
    normalize_list_input,
    normalize_dict_list,
    parse_list_query,
    get_function,
    paginate,
    pattern_filter,
)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idasync
def lookup_funcs(
    queries: Annotated[
        list[str] | str,
        "函数地址或名称，支持: hex(0x401000)、十进制、sub_401000、符号名(main/start)。可传字符串、逗号分隔串或数组。示例: 'main'、'0x401000, start'",
    ],
) -> list[dict]:
    """按地址或名称查找函数。输入: 地址(0x401000/401000/sub_401000)或符号名(main,start)。输出: addr,name,size。支持批量。"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion | str,
        "要转换的数: 字符串'0x41'/'255'、数组['0x41','255']、对象{'text':'0x1000','size':32}。输出 decimal/hex/ascii/binary。LLM 切勿自行做进制转换，请用此工具。",
    ],
) -> list[dict]:
    """数值进制转换。输入任意格式数(0x/十进制)，输出 decimal/hex/ascii/binary。禁止 LLM 手算进制，必须调用此工具。"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "查询: glob过滤'main'、分页简写'0:50'(表示从第0个起取50个，非地址范围)、对象{filter,offset,count}。",
    ],
) -> list[Page[Function]]:
    """列出函数。支持 glob 过滤、分页。'0:50'=offset:count（列表索引，非地址）。"""
    queries = normalize_dict_list(queries, parse_list_query)
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "查询: glob'g_'、分页'0:20'(offset:count 列表索引，非地址)、对象{filter,offset,count}。",
    ],
) -> list[Page[Global]]:
    """列出全局变量。支持 glob 过滤、分页。'0:20'=offset:count（列表索引，非地址）。"""
    queries = normalize_dict_list(queries, parse_list_query)
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "起始索引，从 0 开始"],
    count: Annotated[int, "返回数量，0 表示全部"],
) -> Page[Import]:
    """列出导入表。返回 addr, imported_name, module。用于查动态链接/API 调用。"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "正则表达式，在 IDA 识别的字符串中搜索。例: 'error|fail'、'password'"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """在二进制字符串中按正则搜索。返回 addr,string。不区分大小写。用于找硬编码字符串。"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }
