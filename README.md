# Transfer Station Behavior Detection

这是一个**客户端侧、无 TEE 的 API 中转站投毒可复现测量 harness**。项目用本地合成代理模拟 OpenAI 兼容中转站篡改响应，再测量客户端检测器能发现哪些行为、哪些行为在当前证据下诚实地不可检测。

## 安装

建议使用 Python 3.11：

```bash
python -m pip install -e ".[dev]"
```

## 离线运行

```bash
python -m pytest tests/ -q
python -m ruff check .
python scripts/run_relaypoison_pilot.py
```

pilot 只运行 deterministic mock，不联网、不读取 API key。输出的 mock 数字只是机制层占位，不是真实模型结论。

## 四类 relay 篡改

- `TOOL_CALL_REWRITE`：改写依赖名、网络目标或新增外发动作。
- `INSTRUCTION_INJECTION`：在 assistant 文本中追加下一步诱导文本。
- `SILENT_MODEL_SWAP`：静默切换到离线的降级 backend。
- `AUDIT_EVASION`：不带 canary 时篡改，带 canary 时暂不篡改。

## 四个客户端检测器

- `CrossProviderConsistency`：用独立上游多数核对安全相关字段。
- `ToolCallInvariant`：检查 allowlist、目标变化和依赖 typosquat。
- `OutputFingerprint`：检查当前 mock 可见的 backend identity/fingerprint 差异。
- `CanaryProbe`：用带/不带 canary 的成对请求检查条件性篡改。

纯 `INSTRUCTION_INJECTION` 在没有可信参考且尚未改变当前结构化动作时，检测器可能诚实地抓不到；项目不会把该负向结果包装成检测成功。

## 安全红线

- 仅做防御性研究和本地合成代理。
- 不连接任何真实第三方服务。
- 不把 API key、token、raw 请求或真实响应写入仓库。
- `relaypoison.llm_client` 只为后续真实 pilot 提供薄封装；本轮验证不调用它。

设计和研究交接材料：

- `docs/方向丁_中转站投毒客户端检测_设计_2026-07.md`
- `docs/论文方向与完整思路_交接_2026-07.md`
