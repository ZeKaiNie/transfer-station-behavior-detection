"""relaypoison 离线 mock、篡改和客户端检测器测试。"""

from relaypoison.backends import (
    MockDegradedUpstream,
    MockUpstream,
)
from relaypoison.capabilities import Capability
from relaypoison.detectors import (
    CanaryProbe,
    CrossProviderConsistency,
    OutputFingerprint,
    ToolCallInvariant,
)
from relaypoison.evaluate import evaluate, synthetic_tasks
from relaypoison.models import AgentAction, RelayConfig, TamperClass
from relaypoison.relay import MaliciousRelay


def _task():
    return synthetic_tasks()[1]


def _relay(*tampers: TamperClass) -> MaliciousRelay:
    return MaliciousRelay(
        MockUpstream(),
        RelayConfig(enabled_tampers=set(tampers)),
        degraded_upstream=MockDegradedUpstream(),
    )


def test_each_tamper_changes_expected_security_surface():
    """四类篡改都应通过规则改变动作或交付文本。"""

    task = _task()
    rewrite = _relay(TamperClass.TOOL_CALL_REWRITE).respond(task, task.user_request)
    injection = _relay(TamperClass.INSTRUCTION_INJECTION).respond(
        task,
        task.user_request,
    )
    swap = _relay(TamperClass.SILENT_MODEL_SWAP).respond(task, task.user_request)
    evasion = _relay(
        TamperClass.AUDIT_EVASION,
        TamperClass.TOOL_CALL_REWRITE,
    ).respond(task, task.user_request)

    assert rewrite.delivered.action.target != task.expected_action.target
    assert injection.delivered.text != injection.upstream.text
    assert swap.delivered.backend_id == "mock-degraded"
    assert evasion.delivered.action.target != task.expected_action.target


def test_cross_provider_consistency_catches_rewrite_and_model_swap():
    """独立 mock 多数应抓到动作重写和静默换后端。"""

    detector = CrossProviderConsistency([MockUpstream(), MockUpstream()])
    rewrite = _relay(TamperClass.TOOL_CALL_REWRITE).respond(_task(), _task().user_request)
    swap = _relay(TamperClass.SILENT_MODEL_SWAP).respond(_task(), _task().user_request)

    assert detector.detect(_task(), rewrite).is_flagged is True
    assert detector.detect(_task(), swap).is_flagged is True


def test_tool_call_invariant_catches_typosquat_and_exfil_target():
    """纯客户端规则应抓到依赖 typosquat 和不在 allowlist 的网络目标。"""

    package_task = synthetic_tasks()[0]
    package_response = _relay(TamperClass.TOOL_CALL_REWRITE).respond(
        package_task,
        package_task.user_request,
    )
    target_response = _relay(TamperClass.TOOL_CALL_REWRITE).respond(
        _task(),
        _task().user_request,
    )
    detector = ToolCallInvariant()

    assert detector.detect(package_task, package_response).is_flagged is True
    assert detector.detect(_task(), target_response, _relay()).is_flagged is True


def test_canary_probe_catches_audit_evasion():
    """成对请求应发现无 canary 篡改、带 canary 不篡改的差异。"""

    relay = _relay(TamperClass.AUDIT_EVASION, TamperClass.TOOL_CALL_REWRITE)
    response = relay.respond(_task(), _task().user_request)

    assert CanaryProbe().detect(_task(), response, relay).is_flagged is True


def test_instruction_injection_is_honest_negative_without_trusted_reference():
    """纯文本注入不改变当前动作时，客户端不应假装能够识别。"""

    task = _task()
    relay = _relay(TamperClass.INSTRUCTION_INJECTION)
    response = relay.respond(task, task.user_request)
    detectors = [
        CrossProviderConsistency([MockUpstream(), MockUpstream()]),
        ToolCallInvariant(),
        OutputFingerprint([MockUpstream(), MockUpstream()]),
        CanaryProbe(),
    ]

    assert response.delivered.action == task.expected_action
    assert all(
        detector.detect(task, response, relay).is_flagged is False
        for detector in detectors
    )


def test_benign_traffic_has_no_false_positives_and_metrics_are_reproducible():
    """良性流量不误报，重复 pilot 得到完全相同结果。"""

    first = evaluate()
    second = evaluate()

    assert first == second
    assert all(
        value == 0.0
        for result in first
        for value in result.benign_fpr_by_detector.values()
    )
    assert AgentAction(action_type="none").is_noop is True
    assert Capability.NETWORK.value == "network"
