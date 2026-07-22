"""独立的 OpenAI 兼容 HTTP 客户端。

API key 只从调用方指定的环境变量读取，不写入源码、配置或日志。
本轮离线测试不会调用这个函数。
"""

from __future__ import annotations

import os

import httpx


def call_openai_compatible(
    prompt: str,
    api_base: str,
    model: str,
    api_key_env: str,
    temperature: float = 0.0,
    max_tokens: int = 256,
    timeout: float = 60.0,
) -> str:
    """调用 OpenAI 兼容 chat/completions 接口并返回文本内容。"""

    api_key = os.getenv(api_key_env, "")
    if not api_key:
        raise RuntimeError(
            f"未找到 API key，请设置环境变量 {api_key_env}；客户端不会保存 key。"
        )
    response = httpx.post(
        f"{api_base.rstrip('/')}/chat/completions",
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]
