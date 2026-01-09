# IDA Pro MCP 中文指南

> 详细功能说明请参阅 [README.md](./README.md)

**要求**: Python 3.11+, IDA Pro 8.3+ (推荐 9.0+)

## 快速开始

```bash
# 从 GitHub 安装
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip

# 或本地安装
git clone https://github.com/mrexodia/ida-pro-mcp.git
cd ida-pro-mcp && pip install -e .

# 安装插件和配置 MCP 客户端
ida-pro-mcp --install
```

### 启动服务

```bash
# 1. 启动协调服务器（保持运行）
ida-mcp-coordinator

# 2. 打开 IDA，按 Ctrl+Alt+M (macOS: Ctrl+Option+M) 启动 MCP 插件

# 3. 重启 MCP 客户端 (Cursor 等)
```

## 多实例模式

同时分析多个二进制文件时使用。

### 启动流程

```bash
# 1. 启动协调服务器
ida-mcp-coordinator

# 2. 打开多个 IDA，各自按 Ctrl+Alt+M 启动
#    每个实例会自动分配不同端口并注册到协调服务器
```

### MCP 客户端配置

修改 `~/.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "ida-mcp-coordinator"
    }
  }
}
```

### 实例管理

| 工具 | 说明 |
|------|------|
| `instance_list` | 列出所有实例 |
| `instance_switch` | 切换当前实例 |
| `instance_current` | 查看当前实例 |

## 端口说明

| 服务 | 端口 |
|------|------|
| 协调服务器 | 8801 |
| IDA 实例 (单实例模式) | 13337 |
| IDA 实例 (多实例模式) | 10000+ (动态分配) |
| idalib | 8745 (默认) |

## 常见问题

**Q: 按 G 键跳转失败？**

更新到最新版本后重启 IDA：
```bash
pip install --upgrade https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
```

**Q: 支持 IDA Free 吗？**

不支持，IDA Free 没有插件 API。

**Q: 协调服务器有什么用？**

允许 AI 同时访问多个 IDA 实例。单文件分析不需要。
