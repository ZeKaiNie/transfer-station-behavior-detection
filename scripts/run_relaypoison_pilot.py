"""运行 relaypoison 的离线 mock 测量 pilot。"""

from __future__ import annotations

from relaypoison.evaluate import evaluate, synthetic_tasks


def main() -> None:
    """打印每类篡改的真实计算指标。"""

    results = evaluate()
    detector_names = list(results[0].detection_rate_by_detector)
    print("=== relaypoison offline mock pilot ===")
    print(f"tasks={len(synthetic_tasks())}; no network; no API key")
    print("篡改类别\t无检测到达率\t" + "\t".join(f"{name} 检测率" for name in detector_names))
    for result in results:
        detection = "\t".join(
            f"{result.detection_rate_by_detector[name]:.3f}"
            for name in detector_names
        )
        print(
            f"{result.tamper_class.value}\t"
            f"{result.attack_reach_rate_without_detector:.3f}\t{detection}"
        )
    print("\n=== attack reach after detector ===")
    print("篡改类别\t" + "\t".join(detector_names))
    for result in results:
        reach = "\t".join(
            f"{result.attack_reach_rate_by_detector[name]:.3f}"
            for name in detector_names
        )
        print(f"{result.tamper_class.value}\t{reach}")
    print("\n=== benign FPR ===")
    for result in results:
        values = ", ".join(
            f"{name}={value:.3f}"
            for name, value in result.benign_fpr_by_detector.items()
        )
        print(f"{result.tamper_class.value}: {values}")
    print("\n=== honest limitations ===")
    for result in results:
        for note in result.notes:
            print(f"{result.tamper_class.value}: {note}")


if __name__ == "__main__":
    main()
