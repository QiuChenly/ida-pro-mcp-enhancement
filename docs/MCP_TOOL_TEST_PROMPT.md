# IDA Pro MCP 工具完整测试提示词

> 用于指导 AI 或人工系统化测试 IDA MCP 函数，验证传参、数据解析与行为正确性。

---

## 零、一键复制：AI 测试指令（可直接发给 AI）

```
请按以下规则系统化测试 IDA Pro MCP 工具（user-ida-pro-mcp）：

1. 对每个工具，依次尝试：字符串、对象、数组三种传参格式（若 schema 支持）
2. 覆盖地址格式：0x401000、401000、sub_401000、符号名、非法值
3. 测试空值与边界：""、[]、{}、count=0、超长输入
4. 记录每次调用的「输入 → 输出/错误」，判断是否符合预期
5. 重点检查：get_bytes 支持 `"addr:size"` 字符串格式，list_funcs 的 `"0:50"` 为 offset:count（列表索引，非地址范围）

优先测试：instance_list、int_convert、list_funcs、decompile、get_bytes、lookup_funcs、rename。
```

---

## 一、测试前准备

1. **环境**：IDA Pro 已加载二进制（建议用小型可执行文件，如 `/bin/ls` 或简单 PE）
2. **连接**：IDA 插件已启动 MCP 服务，Broker 运行中
3. **工具**：通过 MCP 客户端（如 Cursor、MCP Inspector）调用 `user-ida-pro-mcp` 服务器工具

---

## 二、测试原则

- **参数格式多样性**：每个工具应测试 `str`、`object`、`array` 三种传入方式（若 schema 支持）
- **边界与异常**：空值、非法值、超长输入
- **地址格式**：`0x401000`、`401000`（十进制）、`sub_401000`、符号名
- **记录**：对每次调用记录「输入 → 输出/错误」，判断是否符合预期

---

## 三、测试用例清单

### 3.1 实例管理（无需 IDA 加载）

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `instance_list` | `{}` | 返回实例列表，至少包含当前连接 |
| `instance_current` | `{}` | 返回当前实例 id、name、binary_path 等 |
| `instance_switch` | `{"instance_id": "<有效id>"}` | 切换成功或无错误 |
| `instance_info` | `{"instance_id": "<有效id>"}` | 返回该实例详情 |

---

### 3.2 数值转换（无 IDA 依赖）

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `int_convert` | `{"inputs": "0x41"}` | 返回 decimal=65, hex=0x41, ascii="A" |
| `int_convert` | `{"inputs": ["0x41", "255"]}` | 返回两个转换结果 |
| `int_convert` | `{"inputs": {"text": "0x1000", "size": 32}}` | 按 32 位解析 |
| `int_convert` | `{"inputs": "not_a_number"}` | 返回 error，无 crash |
| `int_convert` | `{"inputs": ""}` | 正确处理空字符串 |

---

### 3.3 核心查询

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `list_funcs` | `{"queries": "main"}` | 返回匹配 "main" 的函数列表 |
| `list_funcs` | `{"queries": {"offset": 0, "count": 5}}` | 返回前 5 个函数，含 `data`、`next_offset` |
| `list_funcs` | `{"queries": ["*", ""]}` | 两个查询，第二个为全量（filter 为空） |
| `list_funcs` | `{"queries": "0:50"}` | 返回前 50 个函数（0:50=offset:count 列表索引，非地址范围） |
| `list_globals` | `{"queries": "g_"}` | 返回名称含 "g_" 的全局变量 |
| `imports` | `{"offset": 0, "count": 10}` | 返回前 10 个导入 |
| `lookup_funcs` | `{"queries": "main"}` | 按名称查找 |
| `lookup_funcs` | `{"queries": "main, 0x401000"}` | 逗号分隔，两个查询 |
| `lookup_funcs` | `{"queries": ["sub_401000", "start"]}` | 数组格式 |

---

### 3.4 反汇编与反编译

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `decompile` | `{"addr": "0x401000"}` | 返回伪代码或 error |
| `decompile` | `{"addr": "start"}` | 按符号名解析（若存在） |
| `decompile` | `{"addr": "401000"}` | 十进制地址应能解析 |
| `decompile` | `{"addr": "invalid_addr_xyz"}` | 返回明确 error，无 crash |
| `disasm` | `{"addr": "0x401000"}` | 返回汇编行列表 |

---

### 3.5 内存读写

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `get_bytes` | `{"regions": {"addr": "0x401000", "size": 16}}` | 返回 16 字节 hex |
| `get_bytes` | `{"regions": [{"addr": "0x401000", "size": 8}, {"addr": "0x402000", "size": 4}]}` | 批量读取 |
| `get_bytes` | `{"regions": "0x401000:16"}` | 支持 `"addr:size"` 及 `"addr1:size1, addr2:size2"` |
| `get_int` | `{"queries": {"addr": "0x401000", "ty": "u32le"}}` | 返回整数 |
| `get_int` | `{"queries": [{"addr": "0x401000", "ty": "i8"}]}` | 有符号 8 位 |
| `get_string` | `{"addrs": "0x403000"}` | 返回该地址处的字符串 |
| `get_string` | `{"addrs": "0x403000, 0x403010"}` | 逗号分隔多地址 |
| `get_global_value` | `{"queries": "global_var_name"}` | 按名称或地址取值 |

---

### 3.6 交叉引用与调用

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `xrefs_to` | `{"addrs": "0x401000"}` | 引用该地址的 xref 列表 |
| `xrefs_to` | `{"addrs": "0x401000, 0x402000"}` | 多地址 |
| `xrefs_to` | `{"addrs": ["0x401000"], "limit": 5}` | 最多 5 条 |
| `callees` | `{"addrs": "0x401000"}` | 该函数调用的目标列表 |
| `basic_blocks` | `{"addrs": "0x401000"}` | 基本块及后继 |

---

### 3.7 搜索

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `find_regex` | `{"pattern": "error|fail", "limit": 10}` | 字符串中匹配 |
| `find_bytes` | `{"patterns": "48 8B ?? ?? ?? ?? ?? ??"}` | 字节模式搜索 |
| `find_bytes` | `{"patterns": ["48 8B", "FF 15"]}` | 多个模式 |

---

### 3.8 修改操作（谨慎，建议用测试 IDB）

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `set_comments` | `{"items": {"addr": "0x401000", "comment": "test"}}` | 成功或明确 error |
| `rename` | `{"batch": {}}` | 返回空对象，无 crash |
| `rename` | `{"batch": {"func": [{"addr": "0x401000", "name": "__test__"}]}}` | 重命名结果 |
| `patch_asm` | `{"items": {"addr": "0x401000", "asm": "nop"}}` | 汇编补丁 |
| `define_func` | `{"items": {"addr": "0x401050"}}` | 在指定地址定义函数 |

---

### 3.9 类型与结构

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `read_struct` | `{"queries": {"addr": "0x403000"}}` | 读取该地址结构 |
| `search_structs` | `{"filter": "FILE*"}` | 名称匹配的结构 |
| `declare_type` | `{"decls": "typedef int my_t;"}` | 声明类型 |
| `infer_types` | `{"addrs": "0x401000"}` | 类型推断 |

---

### 3.10 栈与调试（调试类需 `--unsafe`）

| 工具 | 测试输入 | 预期 |
|------|----------|------|
| `stack_frame` | `{"addrs": "0x401000"}` | 栈帧变量 |
| `stack_frame` | `{"addrs": "0x401000, 0x402000"}` | 多个函数 |

---

## 四、传参异常与数据异常重点检查

### 4.1 类型不匹配

- 传 `str` 给仅接受 `object`/`array` 的参数 → 视实现而定。验证 `get_bytes.regions` 是否支持 `"addr:size"` 字符串及 JSON 字符串
- 传 `array` 给仅接受 `str` 的参数 → 视实现，或报错或兼容

### 4.2 地址格式

- `0x401000`、`401000`、`0x140001000`（64 位）
- `sub_401000`、`start`、`main`（符号名）
- `invalid`、`0xGGGG`（非法）→ 应有明确错误信息

### 4.3 批量参数格式

- 逗号分隔字符串：`"addr1, addr2"`
- JSON 数组：`["addr1", "addr2"]`
- 对象数组：`[{"addr": "0x401000", "size": 16}]`

### 4.4 空与边界

- 空字符串 `""`
- 空数组 `[]`
- 空对象 `{}`
- `count=0`、`limit=0`
- 超大 `count`/`limit`

---

## 五、执行方式与记录模板

**执行方式**：按节 3 逐项调用 MCP 工具，记录：

```
工具名: ____________
输入: ____________
输出/错误: ____________
结论: ✓ 通过 / ✗ 失败 / ⚠ 异常但可接受
备注: ____________
```

**汇总**：在测试结束时整理：
- 通过 / 失败数量
- 发现的问题清单（含复现步骤）
- 建议改进（参数格式、错误提示、schema 文档）

---

## 六、快速回归用例（最小集）

若时间有限，至少执行：

1. `instance_list` + `instance_current`
2. `int_convert`（str / array / object 各一次）
3. `list_funcs`（str 与 object 各一次）
4. `decompile`（有效地址 + 无效地址）
5. `get_bytes`（object 与 array）
6. `lookup_funcs`（逗号分隔字符串）
7. `rename`（空 batch）
8. `get_bytes` 传 str `"0x401000:16"` 及 JSON 字符串（如 `"[{\"addr\":\"0x401000\",\"size\":16}]"`）→ 应成功返回字节数据
