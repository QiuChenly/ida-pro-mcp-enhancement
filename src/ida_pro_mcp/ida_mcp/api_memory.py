"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

import json
import re

from typing import Annotated
import ida_bytes
import idaapi
import idc

from .rpc import tool
from .sync import idasync
from .utils import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
    normalize_list_input,
    parse_address,
)


# ============================================================================
# Memory Reading Operations
# ============================================================================


def _strip_quotes(s: str) -> str:
    """Remove surrounding quotes (matched or stray) left by JSON/string serialization."""
    s = s.strip().strip('"\'')
    return s.strip()


def _parse_region_str(s: str) -> MemoryRead:
    """Parse 'addr:size' string to MemoryRead dict (e.g. '0x401000:16'). Tolerates surrounding quotes."""
    s = _strip_quotes(s.strip())
    if ":" in s:
        addr_part, size_part = s.split(":", 1)
        addr_part = _strip_quotes(addr_part)
        size_part = _strip_quotes(size_part)
        return {
            "addr": addr_part,
            "size": int(size_part, 0),
        }
    raise ValueError(f"Expected 'addr:size' format, got: {s}")


def _normalize_regions(regions: list[MemoryRead] | MemoryRead | str) -> list[MemoryRead]:
    """Normalize regions to list[MemoryRead]. Accepts dict, list[dict], str 'addr:size', or JSON string '[{addr,size}]'."""
    if isinstance(regions, dict):
        return [regions]
    if isinstance(regions, str):
        s = regions.strip().strip('"\'')
        if len(s) > 1 and (s[0] == "{" or s[0] == "["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return [parsed]
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
        parts = [p.strip().strip('"\'') for p in s.split(",") if p.strip()]
        return [_parse_region_str(p) for p in parts]
    return regions if isinstance(regions, list) else []


@tool
@idasync
def get_bytes(
    regions: Annotated[
        list[MemoryRead] | MemoryRead | str,
        "内存区域。格式: {addr,size}、数组、或字符串'addr:size'(例'0x401000:16'、'0x401000:16, 0x402000:8')。",
    ],
) -> list[dict]:
    """从内存读取原始字节。输入格式: 对象{addr,size}、数组、或字符串'addr:size'(例'0x401000:16'、'0x401000:16, 0x402000:8')。返回 addr,data(hex)。"""
    regions = _normalize_regions(regions)
    if not regions:
        return []

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            data = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, size))
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _parse_int_value(text: str, signed: bool, bits: int) -> int:
    if text is None:
        raise ValueError("Missing integer value")

    value_text = str(text).strip()
    try:
        value = int(value_text, 0)
    except ValueError:
        raise ValueError(f"Invalid integer value: {text}")

    if not signed and value < 0:
        raise ValueError(f"Negative value not allowed for u{bits}")

    return value


@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "整数读取: {addr,ty}。ty 格式: i8/u8/i16le/i16be/u32le/u64。例: {addr:'0x401000',ty:'u32le'}",
    ],
) -> list[dict]:
    """从指定地址按类型读整数。支持有符号(i)无符号(u)、8/16/32/64位、大小端(le/be)。返回 addr,ty,value。"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for item in queries:
        addr = item.get("addr", "")
        ty = item.get("ty", "")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            ea = parse_address(addr)
            size = bits // 8
            data = ida_bytes.get_bytes(ea, size)
            if not data or len(data) != size:
                raise ValueError(f"Failed to read {size} bytes at {addr}")

            value = int.from_bytes(data, byte_order, signed=signed)
            results.append(
                {"addr": addr, "ty": normalized, "value": value, "error": None}
            )
        except Exception as e:
            results.append({"addr": addr, "ty": ty, "value": None, "error": str(e)})

    return results


@tool
@idasync
def get_string(
    addrs: Annotated[
        list[str] | str,
        "地址，支持 hex/十进制/逗号分隔。例: '0x403000' 或 '0x403000, 0x403010'",
    ],
) -> list[dict]:
    """从地址读取 IDA 识别的字符串(C/宽字符)。返回 addr,value。若该址无字符串则 error。"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                results.append(
                    {"addr": addr, "value": None, "error": "No string at address"}
                )
                continue
            value = raw.decode("utf-8", errors="replace")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            # Fallback: try idc.get_item_size or read 4 bytes for typical int/bool
            try:
                size = idc.get_item_size(ea)
            except Exception:
                size = 0
            if size == 0:
                # Last resort: assume 4-byte scalar (int32/bool), common for globals
                try:
                    return hex(ida_bytes.get_dword(ea))
                except Exception:
                    raise IDAError(
                        f"No type info at {ea:#x}. Use get_bytes with explicit size to read raw bytes."
                    )
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if not raw:
            return '""'
        return_string = raw.decode("utf-8", errors="replace").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str,
        "全局变量地址或名称。例: '0x403000'、'globalVar'、'isDemoVersion'。按类型解析返回值。",
    ],
) -> list[dict]:
    """按地址或符号名读取全局变量值。自动识别 hex 地址 vs 名称。需 IDA 已定义该全局类型。"""
    from .utils import looks_like_address

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value, "error": None})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results


@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "Integer write requests (ty, addr, value). value is a string; supports 0x.. and negatives",
    ],
) -> list[dict]:
    """Write integer values to memory addresses"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr = item.get("addr", "")
        ty = item.get("ty", "")
        value_text = item.get("value")

        try:
            bits, signed, byte_order, normalized = _parse_int_class(ty)
            value = _parse_int_value(value_text, signed, bits)
            size = bits // 8
            try:
                data = value.to_bytes(size, byte_order, signed=signed)
            except OverflowError:
                raise ValueError(f"Value {value_text} does not fit in {normalized}")

            ea = parse_address(addr)
            ida_bytes.patch_bytes(ea, data)
            results.append(
                {
                    "addr": addr,
                    "ty": normalized,
                    "value": str(value_text),
                    "ok": True,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "ty": ty,
                    "value": str(value_text) if value_text is not None else None,
                    "ok": False,
                    "error": str(e),
                }
            )

    return results
