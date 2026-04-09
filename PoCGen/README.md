# PoCGen：基于大模型的命令注入（HTTP / Socket）PoC 生成器

PoCGen 将“漏洞描述 + 相关代码片段”转化为可直接落盘的原始 HTTP PoC，请求可选自动验证与多轮迭代，默认聚焦命令注入场景，后续可扩展到 SQLi / SSTI / SSRF 等。

## 亮点
- 一键生成：读取描述与代码文本，输出原始 `.http` 报文（含头与 body）。
- 多轮自修正：支持“采样 → 生成 → 自动验证 → 回调监控”循环，按反馈修正请求直至成功或达最大轮次。
- 自动采样：`--probe-target` 先访问目标获取页面/接口样本，附加进提示词。
- 浏览器采样：`--browser-login` 触发 Playwright 采集中包含登录流程的页面，抓取样本与 Cookie 供提示词参考。
- Socket 事件：新增 `command_injection_socket` handler，输出合法的 Socket.IO 事件 JSON，并自动发包验证。
- 统一输出：`output/poc`（HTTP PoC）、`output/socket`（Socket 事件）、`output/cookie`（浏览器 Cookie/请求响应）。
- 可扩展：处理器（Handler）机制分离漏洞类型与提示词。

## 快速上手
```bash
# 安装依赖（Python 3.9+，推荐 3.10+）
python -m pip install -r PoCGen/requirements.txt

# 最小示例（HTTP）
python -m PoCGen.cli --desc PoCGen/data/desc.txt --code src/*.c

# 带目标提示（仅用于提示词构造）
python -m PoCGen.cli --desc PoCGen/data/desc.txt --code src/*.c --target http://192.168.6.2

# 采样 + 自动验证（如需代理可设 POCGEN_HTTP_PROXY）
python -m PoCGen.cli --desc desc.txt --code src/*.c --target http://192.168.6.2 \
  --probe-target --auto-validate --max-iters 5 --monitor-timeout 15

# 浏览器采样（需要登录态时传入凭证，可叠加 --auto-validate）
python -m PoCGen.cli --code src/*.c --target http://192.168.6.2 \
  --probe-target --browser-login --login-url http://192.168.6.2/ \
  --login-username admin --login-password admin --auto-validate

# Socket.IO 事件示例
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target ws://192.168.6.2:3000/socket.io/?EIO=4&transport=websocket \
  --vuln-type command_injection_socket --auto-validate

提示：浏览器登录流程仅用于采样阶段，自动验证不会复用浏览器 Cookie。
```

生成的 HTTP PoC 以时间戳命名写入 `output/poc`（如 `poc_20250101_120000_01.http`），Socket.IO 事件写入 `output/socket/socket_poc_<ts>_nn.json`，重名自动加序号。

## 目录速览
- `config/`：配置加载，含默认模型与输出目录设置。
- `llm/`：OpenAI SDK 封装，发送系统/用户消息给大模型。
- `prompts/`：提示词模板与拼装函数（当前 `command_injection_http`）。
- `core/`：主流程、数据模型、解析与校验、采样、验证、监控。
- `cli.py`：命令行入口。
- `tests/`：提示与解析的最小单测。
- `output/`：默认输出根（PoC / cookie）。
- `tools/`：预留工具位。

## 配置（环境变量）
| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `POCGEN_QWEN_BASE_URL` / `POCGEN_QWEN_API_KEY` / `POCGEN_QWEN_MODEL` | Qwen 提供商配置 | http://222.20.126.36:30000/v1 / QWEN3@C402 / qwen |
| `POCGEN_DS_BASE_URL` / `POCGEN_DS_API_KEY` / `POCGEN_DS_MODEL` | DeepSeek 提供商配置 | http://222.20.126.32:30000/v1 / DeepseekV3.1_32@C402 / deepseek |
| `POCGEN_DEFAULT_PROVIDER` | 默认模型提供商 | qwen |
| `POCGEN_TIMEOUT` | LLM 请求超时（秒） | 60 |
| `POCGEN_OUTPUT_ROOT` | 输出根目录 | `PoCGen/output` |
| `POCGEN_OUTPUT_DIR` | HTTP PoC 输出目录 | `${OUTPUT_ROOT}/poc` |
| `POCGEN_SOCKET_OUTPUT_DIR` | Socket PoC 输出目录 | `${OUTPUT_ROOT}/socket` |
| `POCGEN_COOKIE_DIR` | 浏览器报文目录 | `${OUTPUT_ROOT}/cookie` |
| `POCGEN_VULN_TYPE` | 漏洞类型 key | command_injection_http |
| `POCGEN_ATTACKER_URL` | payload wget 目标 | `http://192.168.6.1:6666/testpoc` |
| `POCGEN_HTTP_PROXY` | 采样/验证可选代理 | 空 |
| `POCGEN_SAMPLE_TIMEOUT` / `POCGEN_VALIDATION_TIMEOUT` | 采样/验证超时（秒） | 8 / 8 |
| `POCGEN_SAMPLE_PREVIEW` | 采样响应截断长度 | 2000 |
| `POCGEN_MAX_ITERS` | 最大迭代轮次 | 1 |
| `POCGEN_STOP_ON_SUCCESS` | 回调成功后是否提前停止 | true |
| `POCGEN_MONITOR_TIMEOUT` | 每轮等待回调秒数 | 10 |
| `BROWSER_HEADLESS` | 浏览器采样是否无头 | true |
| `POCGEN_SAMPLE_PREVIEW_CHARS` | 采样预览长度（备选字段） | 2000 |

示例（PowerShell）：
```powershell
$env:POCGEN_DEFAULT_PROVIDER = "deepseek"
$env:POCGEN_DS_BASE_URL = "http://222.20.126.32:30000/v1"
$env:POCGEN_DS_API_KEY = "DeepseekV3.1_32@C402"

```

## 工作流程
1) `cli.py` 读取描述与代码 -> 2) 选择漏洞处理器（HTTP / Socket） -> 3) `prompts/templates.py` 拼装系统/用户消息 -> 4) `llm/client.py` 请求模型 -> 5) 处理器对应的 `postprocess.py` 完成分割/校验并保存（`.http` 或 `.json`） -> 6) 可选 `--probe-target` 采样追加到提示词 -> 7) 可选 `--auto-validate` 发送请求并在本地监听 `wget` 回调 -> 8) 将解析/验证/监控结果记录到 `GenerationResult.attempts`。

## 自动采样与验证
- `--probe-target`：预先抓取目标响应，将页面上下文直接追加到提示词以辅助生成。
- `--auto-validate`：生成后立即对目标发包（可经 `POCGEN_HTTP_PROXY` 代理），打印状态与预览，并等待回调。
- `--login-*` / `--browser-login`：通过 Playwright 采集需要登录的页面样本，过程与 Cookie/raw 报文写入 `output/cookie`，日志位于 `logs/playwright_probe.log`。
- `--max-iters` / `--monitor-timeout` / `--stop-on-success`：控制多轮迭代、等待回调时长以及成功即停。

## 输出位置
- PoC 报文：`output/poc/poc_<timestamp>_nn.http`
- Socket 事件：`output/socket/socket_poc_<timestamp>_nn.json`
- 浏览器采样 Cookie / 请求响应：`output/cookie/<ts>-cookies.json` 与 `<ts>-cookie.http`

## 扩展新漏洞类型
1. 在 `prompts/` 添加对应提示词函数。
2. 在 `core/` 新建继承 `VulnHandler` 的处理器。
3. 在 `core/generator.py` 的 `HANDLERS` 注册。
4. 通过 `--vuln-type` 或 `POCGEN_VULN_TYPE` 选择。

## 注意
- 工具生成 PoC 但不会在未开启 `--auto-validate` 时主动发包；请确保使用场景获得授权。
- 模型输出已做最小化解析/校验，如需更严格规范可扩展 `core/command_injection/http/validators.py`。
- “思考模式”默认开启（通过 OpenAI SDK `extra_body`），如需关闭可在配置层调整。

---

如果你提供新的漏洞描述和代码样本，我可以直接运行命令生成一批初版 `.http` PoC 存入 `output/poc/` 供审阅。
