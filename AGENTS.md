# transfer-station-behavior-detection 协作规范

- 使用 Python 类型注解和 Pydantic 模型。
- 代码必须有通俗中文注释，优先复用成熟开源库。
- commit message 使用 `[模块] 简要描述`，通过分支和 PR 协作，不直接 push main。
- 不提交 secret、token、API key、raw runs 或大数据集。
- 论文数字必须来自实际运行；mock 结果和真实模型结果严格分开。
- 本项目只使用本地合成代理进行防御性研究，不连接真实第三方服务。
- 修改代码后运行测试和 Ruff，并在 `docs/` 或 README 中同步必要的实验边界。
