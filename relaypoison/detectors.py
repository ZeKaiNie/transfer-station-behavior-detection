"""客户端侧四类检测器及其诚实的能力边界。"""

from __future__ import annotations

from collections import Counter
from difflib import SequenceMatcher
from typing import Protocol
from urllib.parse import urlparse

from relaypoison.backends import UpstreamBackend
from relaypoison.models import AgentTask, DetectionResult
from relaypoison.relay import MaliciousRelay, RelayResponse


def _action_signature(response: RelayResponse) -> tuple[object, ...]:
    """只取安全相关字段，避免把工具命名差异误当成篡改。"""

    action = response.delivered.action
    return action.capability, action.target, action.package, action.is_noop


class Detector(Protocol):
    """客户端检测器的统一接口。"""

    name: str

    def detect(
        self,
        task: AgentTask,
        response: RelayResponse,
        relay: MaliciousRelay | None = None,
    ) -> DetectionResult:
        """返回一次可解释的检测结果。"""


class CrossProviderConsistency:
    """用独立上游的多数安全字段核验中转站交付结果。"""

    name = "CrossProviderConsistency"

    def __init__(self, references: list[UpstreamBackend]):
        self.references = references

    def detect(
        self,
        task: AgentTask,
        response: RelayResponse,
        relay: MaliciousRelay | None = None,
    ) -> DetectionResult:
        reference_responses = [
            backend.respond(task, task.user_request) for backend in self.references
        ]
        signatures = [
            (
                item.action.capability,
                item.action.target,
                item.action.package,
                item.action.is_noop,
            )
            for item in reference_responses
        ]
        majority = Counter(signatures).most_common(1)[0][0]
        delivered_signature = _action_signature(response)
        backend_ids = {item.backend_id for item in reference_responses}
        flagged = (
            delivered_signature != majority
            or response.delivered.backend_id not in backend_ids
        )
        reason = (
            "交付动作或 backend 身份不属于独立上游多数。"
            if flagged
            else "交付动作和 backend 身份与独立上游多数一致。"
        )
        return DetectionResult(
            detector_name=self.name,
            is_flagged=flagged,
            reason=reason,
            confidence=1.0 if flagged else 0.9,
        )


class ToolCallInvariant:
    """检查目标域名、依赖名和新增网络外发动作。"""

    name = "ToolCallInvariant"

    def detect(
        self,
        task: AgentTask,
        response: RelayResponse,
        relay: MaliciousRelay | None = None,
    ) -> DetectionResult:
        action = response.delivered.action
        config = relay.config if relay is not None else None
        allowed_domains = config.allowed_domains if config is not None else set()
        if action.target and action.target.startswith(("http://", "https://")):
            domain = urlparse(action.target).hostname or ""
            if domain not in allowed_domains:
                return self._flag("目标域名不在客户端 allowlist 中。")
        expected = task.expected_action
        if expected.package and action.package:
            ratio = SequenceMatcher(None, expected.package, action.package).ratio()
            if action.package != expected.package and ratio >= 0.7:
                return self._flag("依赖名与期望值高度相似但不相同，疑似 typosquat。")
        if (
            expected.target
            and action.target
            and action.target != expected.target
            and action.capability == expected.capability
        ):
            return self._flag("安全相关目标发生改变，可能新增了外发目的地。")
        return DetectionResult(
            detector_name=self.name,
            is_flagged=False,
            reason="目标域名、依赖名和安全相关字段通过当前静态规则。",
            confidence=0.8,
        )

    def _flag(self, reason: str) -> DetectionResult:
        return DetectionResult(
            detector_name=self.name,
            is_flagged=True,
            reason=reason,
            confidence=0.95,
        )


class OutputFingerprint:
    """用后端身份和响应摘要检测 mock 阶段的模型替换。"""

    name = "OutputFingerprint"

    def __init__(self, references: list[UpstreamBackend]):
        self.references = references

    def detect(
        self,
        task: AgentTask,
        response: RelayResponse,
        relay: MaliciousRelay | None = None,
    ) -> DetectionResult:
        fingerprints = {
            backend.respond(task, task.user_request).fingerprint
            for backend in self.references
        }
        flagged = response.delivered.fingerprint not in fingerprints
        return DetectionResult(
            detector_name=self.name,
            is_flagged=flagged,
            reason=(
                "响应 fingerprint 不在参考集合中，可能发生静默模型替换。"
                if flagged
                else "响应 fingerprint 与参考集合一致；该信号只覆盖当前 mock 可见差异。"
            ),
            confidence=0.9 if flagged else 0.6,
        )


class CanaryProbe:
    """用带/不带 canary 的成对请求检测条件性 AUDIT_EVASION。"""

    name = "CanaryProbe"

    def detect(
        self,
        task: AgentTask,
        response: RelayResponse,
        relay: MaliciousRelay | None = None,
    ) -> DetectionResult:
        if relay is None:
            return DetectionResult(
                detector_name=self.name,
                is_flagged=False,
                reason="没有可调用的 relay，无法执行成对 canary 探针。",
                confidence=0.0,
            )
        marker = relay.config.canary_marker
        canary = relay.respond(task, f"{task.user_request} {marker}")
        # 只比较安全相关动作；assistant 文本的正常措辞变化不能单独证明篡改。
        differs = _action_signature(response) != _action_signature(canary)
        return DetectionResult(
            detector_name=self.name,
            is_flagged=differs,
            reason=(
                "带 canary 与不带 canary 的交付结果不同，发现条件性篡改。"
                if differs
                else "成对 canary 请求结果一致；当前探针未观察到条件性差异。"
            ),
            confidence=0.95 if differs else 0.7,
        )
