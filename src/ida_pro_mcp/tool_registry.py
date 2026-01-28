"""工具定义解析器

从 ida_mcp/api_*.py 文件中解析工具、资源定义，
生成 MCP 工具 schema，供 server.py 注册使用。

不导入任何IDA模块，仅解析源代码。
"""

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ToolParam:
    """工具参数定义"""
    name: str
    type_str: str  # 原始类型字符串
    description: str
    required: bool = True
    default: Any = None


@dataclass
class ToolDef:
    """工具定义"""
    name: str
    description: str
    params: list[ToolParam] = field(default_factory=list)
    return_type: str = "Any"
    is_unsafe: bool = False
    source_file: str = ""


@dataclass
class ResourceDef:
    """资源定义"""
    uri: str
    name: str
    description: str
    return_type: str = "Any"
    source_file: str = ""


class ToolParser(ast.NodeVisitor):
    """AST解析器，提取@tool和@resource装饰的函数"""
    
    def __init__(self, source_file: str = ""):
        self.tools: list[ToolDef] = []
        self.resources: list[ResourceDef] = []
        self.source_file = source_file
        self._unsafe_funcs: set[str] = set()
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """访问函数定义"""
        decorators = self._get_decorators(node)
        
        # 检查是否有 @unsafe 装饰器
        is_unsafe = "unsafe" in decorators
        
        # 检查 @tool 装饰器
        if "tool" in decorators:
            tool_def = self._parse_tool(node, is_unsafe)
            if tool_def:
                self.tools.append(tool_def)
        
        # 检查 @resource 装饰器
        resource_uri = decorators.get("resource")
        if resource_uri:
            resource_def = self._parse_resource(node, resource_uri)
            if resource_def:
                self.resources.append(resource_def)
        
        self.generic_visit(node)
    
    def _get_decorators(self, node: ast.FunctionDef) -> dict[str, Any]:
        """获取函数的装饰器"""
        decorators = {}
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                # @tool, @unsafe, @idasync
                decorators[dec.id] = True
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    # @resource("uri"), @ext("group")
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        decorators[dec.func.id] = dec.args[0].value
                    else:
                        decorators[dec.func.id] = True
        return decorators
    
    def _parse_tool(self, node: ast.FunctionDef, is_unsafe: bool) -> Optional[ToolDef]:
        """解析工具函数"""
        name = node.name
        description = ast.get_docstring(node) or f"Call {name}"
        params = self._parse_params(node)
        return_type = self._get_return_type(node)
        
        return ToolDef(
            name=name,
            description=description.strip(),
            params=params,
            return_type=return_type,
            is_unsafe=is_unsafe,
            source_file=self.source_file,
        )
    
    def _parse_resource(self, node: ast.FunctionDef, uri: str) -> Optional[ResourceDef]:
        """解析资源函数"""
        name = node.name
        description = ast.get_docstring(node) or f"Resource {uri}"
        return_type = self._get_return_type(node)
        
        return ResourceDef(
            uri=uri,
            name=name,
            description=description.strip(),
            return_type=return_type,
            source_file=self.source_file,
        )
    
    def _parse_params(self, node: ast.FunctionDef) -> list[ToolParam]:
        """解析函数参数"""
        params = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)
        
        for i, arg in enumerate(node.args.args):
            # 跳过 self 参数
            if arg.arg == "self":
                continue
            
            param_name = arg.arg
            type_str = "Any"
            description = ""
            
            # 解析类型注解
            if arg.annotation:
                type_str, description = self._parse_annotation(arg.annotation)
            
            # 检查是否有默认值
            default_idx = i - defaults_offset
            has_default = default_idx >= 0 and default_idx < len(node.args.defaults)
            default_value = None
            if has_default:
                default_node = node.args.defaults[default_idx]
                default_value = self._get_constant_value(default_node)
            
            params.append(ToolParam(
                name=param_name,
                type_str=type_str,
                description=description,
                required=not has_default,
                default=default_value,
            ))
        
        return params
    
    def _parse_annotation(self, node: ast.expr) -> tuple[str, str]:
        """解析类型注解，返回 (type_str, description)"""
        # Annotated[type, "description"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id == "Annotated":
                if isinstance(node.slice, ast.Tuple) and len(node.slice.elts) >= 2:
                    type_node = node.slice.elts[0]
                    desc_node = node.slice.elts[1]
                    type_str = self._node_to_type_str(type_node)
                    description = ""
                    if isinstance(desc_node, ast.Constant):
                        description = str(desc_node.value)
                    return type_str, description
            # 其他泛型类型如 list[str], Optional[int]
            return self._node_to_type_str(node), ""
        
        # 简单类型
        return self._node_to_type_str(node), ""
    
    def _node_to_type_str(self, node: ast.expr) -> str:
        """将AST节点转换为类型字符串"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Subscript):
            base = self._node_to_type_str(node.value)
            if isinstance(node.slice, ast.Tuple):
                args = ", ".join(self._node_to_type_str(e) for e in node.slice.elts)
            else:
                args = self._node_to_type_str(node.slice)
            return f"{base}[{args}]"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            # Union type: int | str
            left = self._node_to_type_str(node.left)
            right = self._node_to_type_str(node.right)
            return f"{left} | {right}"
        elif isinstance(node, ast.Attribute):
            return f"{self._node_to_type_str(node.value)}.{node.attr}"
        return "Any"
    
    def _get_return_type(self, node: ast.FunctionDef) -> str:
        """获取返回类型"""
        if node.returns:
            return self._node_to_type_str(node.returns)
        return "Any"
    
    def _get_constant_value(self, node: ast.expr) -> Any:
        """获取常量值"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.List):
            return [self._get_constant_value(e) for e in node.elts]
        elif isinstance(node, ast.Dict):
            return {
                self._get_constant_value(k): self._get_constant_value(v)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }
        elif isinstance(node, ast.Name) and node.id == "None":
            return None
        return None


def parse_api_file(filepath: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """解析单个API文件"""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"[tool_registry] 解析错误 {filepath}: {e}")
        return [], []
    
    parser = ToolParser(source_file=os.path.basename(filepath))
    parser.visit(tree)
    
    return parser.tools, parser.resources


def parse_all_api_files(api_dir: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """解析目录下所有 api_*.py 文件"""
    all_tools: list[ToolDef] = []
    all_resources: list[ResourceDef] = []
    
    if not os.path.isdir(api_dir):
        print(f"[tool_registry] 目录不存在: {api_dir}")
        return all_tools, all_resources
    
    for filename in sorted(os.listdir(api_dir)):
        if filename.startswith("api_") and filename.endswith(".py"):
            # 跳过 api_instances.py（这是连接管理，不是IDA工具）
            if filename == "api_instances.py":
                continue
            
            filepath = os.path.join(api_dir, filename)
            tools, resources = parse_api_file(filepath)
            all_tools.extend(tools)
            all_resources.extend(resources)
    
    return all_tools, all_resources


def type_str_to_json_schema(type_str: str) -> dict:
    """将类型字符串转换为JSON Schema"""
    type_str = type_str.strip()
    
    # 处理 Union 类型 (int | str)
    if " | " in type_str:
        parts = [p.strip() for p in type_str.split(" | ")]
        # 简化处理：返回第一个非None类型
        for p in parts:
            if p.lower() not in ("none", "nonetype"):
                return type_str_to_json_schema(p)
        return {"type": "null"}
    
    # 处理 Optional[T]
    if type_str.startswith("Optional[") and type_str.endswith("]"):
        inner = type_str[9:-1]
        return type_str_to_json_schema(inner)
    
    # 处理 list[T]
    if type_str.startswith("list[") and type_str.endswith("]"):
        inner = type_str[5:-1]
        return {"type": "array", "items": type_str_to_json_schema(inner)}
    
    # 处理 dict[K, V]
    if type_str.startswith("dict[") and type_str.endswith("]"):
        return {"type": "object"}
    
    # 基本类型映射
    type_map = {
        "str": {"type": "string"},
        "int": {"type": "integer"},
        "float": {"type": "number"},
        "bool": {"type": "boolean"},
        "None": {"type": "null"},
        "Any": {},
    }
    
    # 检查是否是已知类型
    base_type = type_str.split("[")[0]
    if base_type in type_map:
        return type_map[base_type]
    
    # 复杂类型（如 TypedDict）作为 object 处理
    return {"type": "object"}


def tool_to_mcp_schema(tool: ToolDef) -> dict:
    """将 ToolDef 转换为 MCP 工具 schema"""
    properties = {}
    required = []
    
    for param in tool.params:
        prop = type_str_to_json_schema(param.type_str)
        if param.description:
            prop["description"] = param.description
        if param.default is not None:
            prop["default"] = param.default
        properties[param.name] = prop
        
        if param.required:
            required.append(param.name)
    
    schema = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
        },
    }
    
    if required:
        schema["inputSchema"]["required"] = required
    
    return schema


def resource_to_mcp_schema(resource: ResourceDef) -> dict:
    """将 ResourceDef 转换为 MCP 资源 schema"""
    return {
        "uri": resource.uri,
        "name": resource.name,
        "description": resource.description,
    }


# ============================================================================
# 测试
# ============================================================================

if __name__ == "__main__":
    import sys
    
    # 获取 api 目录
    script_dir = os.path.dirname(os.path.realpath(__file__))
    api_dir = os.path.join(script_dir, "ida_mcp")
    
    print(f"解析目录: {api_dir}")
    tools, resources = parse_all_api_files(api_dir)
    
    print(f"\n找到 {len(tools)} 个工具:")
    for t in tools:
        params_str = ", ".join(f"{p.name}: {p.type_str}" for p in t.params)
        print(f"  - {t.name}({params_str}) -> {t.return_type}")
        if t.is_unsafe:
            print(f"    [UNSAFE]")
    
    print(f"\n找到 {len(resources)} 个资源:")
    for r in resources:
        print(f"  - {r.uri} -> {r.name}")
