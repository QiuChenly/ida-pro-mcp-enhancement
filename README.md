# IDA Pro MCP

<div align="center">

**[English](#english)** | **[中文](#中文)**

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

</div>

---

<a name="english"></a>
<details open>
<summary><h2>🇺🇸 English Documentation</h2></summary>

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://www.anthropic.com/code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://www.kilocode.com/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

## Installation

Install the latest version of the IDA Pro MCP package:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/QiuChenly/ida-pro-mcp-enhancement/archive/refs/heads/main.zip
```

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

**Important**: Make sure you completely restart IDA and your MCP client for the installation to take effect. Some clients (like Claude) run in the background and need to be quit from the tray icon.

https://github.com/user-attachments/assets/65ed3373-a187-4dd5-a807-425dca1d8ee9

_Note_: You need to load a binary in IDA before the plugin menu will show up.

## Usage (Broker Mode)

```bash
# 1. Start Broker first (required for multi Cursor windows / multi IDA)
uv run ida-pro-mcp --broker
# Or specify port: uv run ida-pro-mcp --broker --port 13337

# 2. Start Cursor, MCP connects via stdio and requests the Broker above

# 3. Open IDA, load binary, press Ctrl+Alt+M to connect (IDA connects to Broker's 13337 port)
```

### Architecture

- **Broker**: Separate process, unique listener on `127.0.0.1:13337`, holds IDA instance registry; both IDA and MCP clients connect to it.
- **MCP Process**: Started by Cursor per window (stdio), **does not bind port**, requests Broker via HTTP.
- **IDA Plugin**: Connects to `127.0.0.1:13337` (Broker).

```
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP        ┌─────────────────┐
│  Cursor Win A   │◄──────────────►│   MCP Process A │─────────────────►│                 │
└─────────────────┘                └─────────────────┘                 │     Broker      │
                                                                        │  (unique :13337)│
┌─────────────────┐     stdio      ┌─────────────────┐     HTTP        │                 │
│  Cursor Win B   │◄──────────────►│   MCP Process B │─────────────────►│   REGISTRY      │
└─────────────────┘                └─────────────────┘                 │                 │
                                                                        └────────▲───────┘
┌─────────────────┐     HTTP register + SSE                               │
│   IDA 1/2       │◄───────────────────────────────────────────────────────┘
└─────────────────┘
```

### Multi-Instance Mode

When analyzing multiple binaries simultaneously, just open multiple IDAs and press Ctrl+Alt+M in each.

| Tool | Description |
|------|-------------|
| `instance_list` | List all connected IDA instances |
| `instance_switch` | Switch current active instance |
| `instance_current` | View current instance info |
| `instance_info` | Get detailed info for specified instance |

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--install` | Install IDA plugin and MCP client configuration |
| `--uninstall` | Uninstall IDA plugin and MCP client configuration |
| `--unsafe` | Enable unsafe tools (debugger related) |
| `--broker` | **Start Broker only** (HTTP), no stdio; run separately for multi-window/multi-IDA |
| `--broker-url URL` | Broker URL for MCP mode, default `http://127.0.0.1:13337` |
| `--port PORT` | Broker mode listen port, default 13337 |
| `--config` | Print MCP configuration info |

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## SSE Transport & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/user-guide/idalib) you can also run a headless SSE server:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## MCP Resources

**Resources** represent browsable state (read-only data) following MCP's philosophy.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (path, arch, base, size, hashes)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Lookups:**
- `ida://import/{name}` - Import details by name
- `ida://export/{name}` - Export details by name
- `ida://xrefs/from/{addr}` - Cross-references from address

## Core Functions

- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `decompile(addr)`: Decompile function at the given address.
- `disasm(addr)`: Disassemble function with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).

## Modification Operations

- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.
- `define_func(items)`: Define function(s) at address(es). Optionally specify `end` for explicit bounds.
- `define_code(items)`: Convert bytes to code instruction(s) at address(es).
- `undefine(items)`: Undefine item(s) at address(es), converting back to raw bytes. Optionally specify `end` or `size`.

## Memory Reading Operations

- `get_bytes(addrs)`: Read raw bytes at address(es).
- `get_int(queries)`: Read integer values using ty (i8/u64/i16le/i16be/etc).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Extension)

Debugger tools are hidden by default. Enable with `--unsafe` flag:

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

**Control:**
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue execution.
- `dbg_run_to(addr)`: Run to address.
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.

**Breakpoints:**
- `dbg_bps()`: List all breakpoints.
- `dbg_add_bp(addrs)`: Add breakpoint(s).
- `dbg_delete_bp(addrs)`: Delete breakpoint(s).
- `dbg_toggle_bp(items)`: Enable/disable breakpoint(s).

**Registers:**
- `dbg_regs()`: All registers, current thread.
- `dbg_regs_all()`: All registers, all threads.
- `dbg_regs_remote(tids)`: All registers, specific thread(s).
- `dbg_gpregs()`: GP registers, current thread.
- `dbg_gpregs_remote(tids)`: GP registers, specific thread(s).
- `dbg_regs_named(names)`: Named registers, current thread.
- `dbg_regs_named_remote(tid, names)`: Named registers, specific thread.

**Stack & Memory:**
- `dbg_stacktrace()`: Call stack with module/symbol info.
- `dbg_read(regions)`: Read memory from debugged process.
- `dbg_write(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).
- `analyze_funcs(addrs)`: Comprehensive function analysis (decompilation, assembly, xrefs, callees, callers, strings, constants, basic blocks).

## Pattern Matching & Search

- `find_regex(queries)`: Search strings with case-insensitive regex (paginated).
- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000.
- `find_insns(sequences, limit=1000, offset=0)`: Find instruction sequence(s) in code. Max limit: 10000.
- `find(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.

## Type Operations

- `set_type(edits)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.
- `put_int(items)`: Write integer values using ty (i8/u64/i16le/i16be/etc).

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects

## Comparison with other MCP servers

There are a few IDA Pro MCP servers floating around, but I created my own for a few reasons:

1. Installation should be fully automated.
2. The architecture of other plugins make it difficult to add new functionality quickly (too much boilerplate of unnecessary dependencies).
3. Learning new technologies is fun!

If you want to check them out, here is a list (in the order I discovered them):

- https://github.com/taida957789/ida-mcp-server-plugin (SSE protocol only, requires installing dependencies in IDAPython).
- https://github.com/fdrechsler/mcp-server-idapro (MCP Server in TypeScript, excessive boilerplate required to add new functionality).
- https://github.com/MxIris-Reverse-Engineering/ida-mcp-server (custom socket protocol, boilerplate).

Feel free to open a PR to add your IDA Pro MCP server here.

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```

</details>

---

<a name="中文"></a>
<details>
<summary><h2>🇨🇳 中文文档</h2></summary>

## 环境要求

- [Python](https://www.python.org/downloads/) (**3.11 或更高版本**)
  - 使用 `idapyswitch` 切换到最新 Python 版本
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 或更高, 推荐 9.0+), **不支持 IDA Free**
- 支持的 MCP 客户端（选择一个）
  - [Cursor](https://cursor.com)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://www.anthropic.com/code)
  - [VS Code](https://code.visualstudio.com/)
  - [其他 MCP 客户端](https://modelcontextprotocol.io/clients#example-clients): 运行 `ida-pro-mcp --config` 获取客户端配置

## 安装

安装最新版本：

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/QiuChenly/ida-pro-mcp-enhancement/archive/refs/heads/main.zip
```

或本地开发安装：

```bash
cd ida-pro-mcp && uv venv && uv pip install -e .
```

配置 MCP 服务器并安装 IDA 插件：

```sh
ida-pro-mcp --install
```

**重要**: 安装后请完全重启 IDA 和 MCP 客户端。某些客户端（如 Claude）在后台运行，需要从托盘图标退出。

_注意_: 需要在 IDA 中加载二进制文件后，插件菜单才会显示。

## 使用方式（Broker 模式）

> ⚠️ **注意**: 当前版本使用 Broker 架构（HTTP :13337），多窗口 Cursor、多 IDA 时需**先单独启动 Broker**。

```bash
# 1. 先启动 Broker（多窗口 Cursor / 多 IDA 时必须，否则连接会超时或 instance_list 为空）
uv run ida-pro-mcp --broker
# 或指定端口: uv run ida-pro-mcp --broker --port 13337

# 2. 启动 Cursor，MCP 会通过 stdio 连接，并请求上述 Broker

# 3. 打开 IDA 加载二进制文件，按 Ctrl+Alt+M 连接（IDA 连到 Broker 的 13337 端口）
```

### 架构说明

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

### 多实例模式

同时分析多个二进制文件时，只需打开多个 IDA 并分别按 Ctrl+Alt+M 连接。

| 工具 | 说明 |
|------|------|
| `instance_list` | 列出所有已连接的 IDA 实例 |
| `instance_switch` | 切换当前活动实例 |
| `instance_current` | 查看当前实例信息 |
| `instance_info` | 获取指定实例的详细信息 |

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

默认情况下，调试器相关工具（`dbg_start`, `dbg_step_into` 等）不会注册。如需使用，需在 MCP 客户端配置中添加 `--unsafe` 参数：

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

## 提示工程

LLM 容易产生幻觉，需要精确的提示。对于逆向工程，整数和字节之间的转换尤其容易出问题。以下是一个最小示例提示：

```md
你的任务是在 IDA Pro 中分析一个 crackme。你可以使用 MCP 工具获取信息。一般使用以下策略：

- 检查反编译并添加发现的注释
- 将变量重命名为更合理的名称
- 必要时更改变量和参数类型（尤其是指针和数组类型）
- 将函数名更改为更具描述性的名称
- 如果需要更多细节，反汇编函数并添加发现的注释
- 绝不要自己转换数字进制。如需要请使用 `int_convert` MCP 工具！
- 不要尝试暴力破解，仅从反汇编和简单的 python 脚本中推导解决方案
- 最后创建 report.md 记录你的发现和步骤
- 找到解决方案时，提示用户反馈你找到的密码
```

## 提高 LLM 准确性的技巧

大型语言模型（LLM）是强大的工具，但有时会在复杂的数学计算中挣扎或出现"幻觉"（编造事实）。确保告诉 LLM 使用 `int_convert` MCP 工具，某些操作可能还需要 [math-mcp](https://github.com/EthanHenrickson/math-mcp)。

另一点需要注意的是，LLM 在混淆代码上表现不佳。在尝试使用 LLM 解决问题之前，先查看二进制文件并花一些时间（自动）移除以下内容：

- 字符串加密
- 导入哈希
- 控制流平坦化
- 代码加密
- 反反编译技巧

你还应该使用 Lumina 或 FLIRT 等工具尝试解析所有开源库代码和 C++ STL，这将进一步提高准确性。

## 核心功能

- `lookup_funcs(queries)`: 按地址或名称获取函数（自动检测，接受列表或逗号分隔字符串）
- `int_convert(inputs)`: 将数字转换为不同格式（十进制、十六进制、字节、ASCII、二进制）
- `list_funcs(queries)`: 列出函数（分页、过滤）
- `list_globals(queries)`: 列出全局变量（分页、过滤）
- `imports(offset, count)`: 列出所有导入符号和模块名（分页）
- `decompile(addr)`: 在给定地址反编译函数
- `disasm(addr)`: 反汇编函数并显示完整详情（参数、栈帧等）
- `xrefs_to(addrs)`: 获取到地址的所有交叉引用
- `xrefs_to_field(queries)`: 获取到特定结构体字段的交叉引用
- `callees(addrs)`: 获取函数调用的其他函数

## 修改操作

- `set_comments(items)`: 在反汇编和反编译视图中设置注释
- `patch_asm(items)`: 在地址处修补汇编指令
- `declare_type(decls)`: 在本地类型库中声明 C 类型

## 内存读取操作

- `get_bytes(addrs)`: 读取原始字节
- `get_int(queries)`: 使用 ty (i8/u64/i16le/i16be 等) 读取整数值
- `get_string(addrs)`: 读取以 null 结尾的字符串
- `get_global_value(queries)`: 按地址或名称读取全局变量值

## 栈帧操作

- `stack_frame(addrs)`: 获取函数的栈帧变量
- `declare_stack(items)`: 在指定偏移处创建栈变量
- `delete_stack(items)`: 按名称删除栈变量

## 结构体操作

- `read_struct(queries)`: 在特定地址读取结构体字段值
- `search_structs(filter)`: 按名称模式搜索结构体

## 高级分析操作

- `py_eval(code)`: 在 IDA 上下文中执行任意 Python 代码
- `analyze_funcs(addrs)`: 综合函数分析（反编译、汇编、交叉引用、调用等）

## 模式匹配与搜索

- `find_regex(queries)`: 使用不区分大小写的正则表达式搜索字符串（分页）
- `find_bytes(patterns)`: 在二进制中查找字节模式（如 "48 8B ?? ??"）
- `find_insns(sequences)`: 在代码中查找指令序列
- `find(type, targets)`: 高级搜索（立即值、字符串、数据/代码引用）

## 控制流分析

- `basic_blocks(addrs)`: 获取基本块及其前驱和后继

## 类型操作

- `set_type(edits)`: 将类型应用于函数、全局变量、局部变量或栈变量
- `infer_types(addrs)`: 使用 Hex-Rays 或启发式方法推断类型

## 导出操作

- `export_funcs(addrs, format)`: 以指定格式导出函数（json、c_header 或 prototypes）

## 图操作

- `callgraph(roots, max_depth)`: 从根函数构建可配置深度的调用图

## 批量操作

- `rename(batch)`: 统一批量重命名（函数、全局变量、局部变量、栈变量）
- `patch(patches)`: 一次修补多个字节序列
- `put_int(items)`: 使用 ty (i8/u64/i16le/i16be 等) 写入整数值

</details>
