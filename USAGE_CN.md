# IDA Pro MCP 中文指南

> 详细功能说明请参阅 [README.md](./README.md)

**要求**: Python 3.11+, IDA Pro 8.3+ (推荐 9.0+)

> ⚠️ **注意**: 当前版本使用 Broker 架构（HTTP :13337），多窗口 Cursor、多 IDA 时需**先单独启动 Broker**。

## 快速开始

```bash
# 本地安装
cd ida-pro-mcp && uv venv && uv pip install -e .

# 安装插件和配置 MCP 客户端
uv run ida-pro-mcp --install
```

### 使用方式

```bash
# 1. 先启动 Broker（多窗口 Cursor / 多 IDA 时必须，否则连接会超时或 instance_list 为空）
uv run ida-pro-mcp --broker
# 或指定端口: uv run ida-pro-mcp --broker --port 13337

# 2. 启动 Cursor，MCP 会通过 stdio 连接，并请求上述 Broker

# 3. 打开 IDA 加载二进制文件，按 Ctrl+Alt+M 连接（IDA 连到 Broker 的 13337 端口）
```

## 架构说明（Broker 模式）

- **Broker**：单独进程，唯一监听 `127.0.0.1:13337`，持有 IDA 实例注册表；IDA 与 MCP 客户端均连到它。
- **MCP 进程**：由 Cursor 按窗口启动（stdio），**不绑定端口**，通过 HTTP 请求 Broker 获取实例列表和转发 IDA 请求。
- **IDA 插件**：连接 `127.0.0.1:13337`（即 Broker）。

```
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP        ┌─────────────────┐
│  Cursor 窗口 A  │◄──────────────►│   MCP 进程 A    │─────────────────►│                 │
└─────────────────┘                └─────────────────┘                 │     Broker      │
                                                                         │  (唯一 :13337)  │
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP        │                 │
│  Cursor 窗口 B  │◄──────────────►│   MCP 进程 B    │─────────────────►│   REGISTRY      │
└─────────────────┘                └─────────────────┘                 │                 │
                                                                         └────────▲───────┘
┌─────────────────┐     HTTP register + SSE                               │
│   IDA 实例 1/2  │◄───────────────────────────────────────────────────────┘
└─────────────────┘
```

**优势**：
- 多 Cursor 窗口、多 IDA 实例共享同一注册表，不再出现「谁抢到端口谁有数据」或连接超时。
- MCP 进程不占端口，无端口冲突。

## 多实例模式

同时分析多个二进制文件时，只需打开多个 IDA 并分别按 Ctrl+Alt+M 连接。

### 实例管理

| 工具 | 说明 |
|------|------|
| `instance_list` | 列出所有已连接的 IDA 实例 |
| `instance_switch` | 切换当前活动实例 |
| `instance_current` | 查看当前实例信息 |
| `instance_info` | 获取指定实例的详细信息 |

## 通信路径

| 角色 | 地址 | 说明 |
|------|------|------|
| Broker | `http://127.0.0.1:13337` | 唯一监听进程，IDA 与 MCP 均连此 |
| MCP（Cursor 启动） | 不监听端口 | 通过 `--broker-url` 请求 Broker |
| IDA 插件 | `127.0.0.1:13337` | 与 Broker 一致 |

可通过环境变量或参数自定义 Broker 地址：

```bash
# MCP 模式指定 Broker 地址
ida-pro-mcp --broker-url http://127.0.0.1:13337
# 或环境变量
IDA_MCP_BROKER_URL=http://127.0.0.1:13337 ida-pro-mcp
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--install` | 安装 IDA 插件和 MCP 客户端配置 |
| `--uninstall` | 卸载 IDA 插件和 MCP 客户端配置 |
| `--unsafe` | 启用不安全工具（调试器相关） |
| `--broker` | **仅启动 Broker**（HTTP），不启动 stdio；多窗口/多 IDA 时请先单独运行 |
| `--broker-url URL` | MCP 模式连接 Broker 的 URL，默认 `http://127.0.0.1:13337` |
| `--port PORT` | Broker 模式监听端口，默认 13337 |
| `--config` | 打印 MCP 配置信息 |

### 启用调试器工具

默认情况下，调试器相关工具（`dbg_start`, `dbg_step_into` 等21个）不会注册。如需使用，需在MCP客户端配置中添加 `--unsafe` 参数：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "uv",
      "args": ["run", "ida-pro-mcp", "--unsafe"]
    }
  }
}
```

## 常见问题

**Q: IDA 插件连接失败 / instance_list 为空？**

采用 Broker 架构时请确保：
1. **先单独启动 Broker**：`uv run ida-pro-mcp --broker`（终端常开）
2. 再启动 Cursor（MCP 会连到上述 Broker）
3. IDA 中按 Ctrl+Alt+M 连接（连到 Broker 的 13337 端口）
4. 若端口被占用，可换端口：`ida-pro-mcp --broker --port 13338`，且 IDA 插件与 MCP 的 broker-url 需一致

**Q: 按 G 键跳转失败？**

更新到最新版本后重启 IDA：
```bash
uv pip install -e .
```

**Q: 如何查看已连接的实例？**

在 MCP 客户端中调用 `instance_list` 工具查看所有已连接的 IDA 实例。

**Q: 支持 IDA Free 吗？**

不支持，IDA Free 没有插件 API。
