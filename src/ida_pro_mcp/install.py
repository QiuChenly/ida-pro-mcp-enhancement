"""IDA Pro MCP 安装工具

安装 IDA 插件和 MCP 客户端配置。
"""

import os
import sys
import json
import shutil
import tempfile
import glob
import tomllib
import tomli_w

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")


def get_python_executable():
    """获取 Python 可执行文件路径"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python
    return sys.executable


def copy_python_env(env: dict[str, str]):
    """复制 Python 环境变量"""
    python_vars = [
        "PYTHONHOME", "PYTHONPATH", "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR", "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE", "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config():
    """生成 MCP 配置"""
    from . import server
    mcp_config = {
        "command": get_python_executable(),
        "args": [server.__file__],
    }
    env = {}
    if copy_python_env(env):
        mcp_config["env"] = env
    return mcp_config


def print_mcp_config():
    """打印 MCP 配置"""
    print(json.dumps({"mcpServers": {"ida-pro-mcp": generate_mcp_config()}}, indent=2))


def install_mcp_servers(*, uninstall=False, quiet=False):
    """安装/卸载 MCP 服务器配置"""
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "VS Code Insiders": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage",
                                   "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage",
                                      "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage",
                                       "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA", ""), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (os.path.join(os.getenv("APPDATA", ""), "Zed"), "settings.json"),
            "Gemini CLI": (os.path.join(os.path.expanduser("~"), ".gemini"), "settings.json"),
            "Warp": (os.path.join(os.path.expanduser("~"), ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(os.path.expanduser("~"), ".aws", "amazonq"), "mcp_config.json"),
            "VS Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(os.getenv("APPDATA", ""), "Code - Insiders", "User"), "settings.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code",
                                   "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code",
                                      "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code",
                                       "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Zed"), "settings.json"),
            "Gemini CLI": (os.path.join(os.path.expanduser("~"), ".gemini"), "settings.json"),
            "BoltAI": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "BoltAI"), "config.json"),
            "Warp": (os.path.join(os.path.expanduser("~"), ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(os.path.expanduser("~"), ".aws", "amazonq"), "mcp_config.json"),
            "VS Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code - Insiders", "User"), "settings.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage",
                                   "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage",
                                      "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage",
                                       "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (os.path.join(os.path.expanduser("~"), ".config", "zed"), "settings.json"),
            "Gemini CLI": (os.path.join(os.path.expanduser("~"), ".gemini"), "settings.json"),
            "Warp": (os.path.join(os.path.expanduser("~"), ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(os.path.expanduser("~"), ".aws", "amazonq"), "mcp_config.json"),
            "VS Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(os.path.expanduser("~"), ".config", "Code - Insiders", "User"), "settings.json"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            if not quiet:
                print(f"Skipping {name}\n  Config: {config_path} (not found)")
            continue

        config = {}
        if os.path.exists(config_path):
            with open(config_path, "rb" if is_toml else "r", encoding=None if is_toml else "utf-8") as f:
                if is_toml:
                    data = f.read()
                    if data:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            continue
                else:
                    data = f.read().strip()
                    if data:
                        try:
                            config = json.loads(data)
                        except json.JSONDecodeError:
                            continue

        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers["ida-pro-mcp"] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if "ida-pro-mcp" not in mcp_servers:
                continue
            del mcp_servers["ida-pro-mcp"]
        else:
            mcp_servers["ida-pro-mcp"] = generate_mcp_config()

        fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=".toml" if is_toml else ".json")
        try:
            with os.fdopen(fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8") as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1

    if not uninstall and installed == 0:
        print("No MCP servers installed. Use --config to generate config manually.")


def install_ida_plugin(*, uninstall=False, quiet=False, allow_ida_free=False):
    """安装/卸载 IDA 插件"""
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if free_licenses:
            print("IDA Free does not support plugins.")
            sys.exit(1)
    
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    loader_dest = os.path.join(ida_plugin_folder, "ida_mcp.py")
    pkg_dest = os.path.join(ida_plugin_folder, "ida_mcp")

    if uninstall:
        for path in [loader_dest, pkg_dest]:
            if os.path.lexists(path):
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                if not quiet:
                    print(f"Removed: {path}")
    else:
        os.makedirs(ida_plugin_folder, exist_ok=True)
        
        for src, dest in [(IDA_PLUGIN_LOADER, loader_dest), (IDA_PLUGIN_PKG, pkg_dest)]:
            if os.path.lexists(dest):
                if os.path.isdir(dest) and not os.path.islink(dest):
                    shutil.rmtree(dest)
                else:
                    os.remove(dest)
            try:
                os.symlink(src, dest)
            except OSError:
                if os.path.isdir(src):
                    shutil.copytree(src, dest)
                else:
                    shutil.copy(src, dest)
        
        if not quiet:
            print(f"Installed IDA plugin to {ida_plugin_folder}")
