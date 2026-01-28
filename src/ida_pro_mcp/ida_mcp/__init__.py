"""IDA Pro MCP Plugin - Modular Package Version（HTTP+SSE 版本）

通过 HTTP+SSE 与 MCP 服务器通信。

架构:
- rpc.py: JSON-RPC infrastructure and registry
- sync.py: IDA synchronization decorator (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations (71 tools + 24 resources)
- api_instances.py: HTTP+SSE 连接管理
"""

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# Import all API modules to register @tool functions and @resource functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources
from . import api_instances

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError, CancelledError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource
from .api_core import init_caches
from .api_instances import (
    connect_to_server,
    disconnect,
    is_connected,
    get_instance_id,
    set_auto_reconnect,
)

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # API modules
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_instances",
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "init_caches",
    # HTTP+SSE 连接管理
    "connect_to_server",
    "disconnect",
    "is_connected",
    "get_instance_id",
    "set_auto_reconnect",
]
