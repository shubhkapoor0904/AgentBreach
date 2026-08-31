import pytest
from src.metrics import MetricEvaluator, SecurityMetrics


def test_metrics_evaluator_computation():
    evaluator = MetricEvaluator()

    attack_u = [
        {"is_compromised": True, "poison_stored": True, "persisted_after_reset": True},
        {"is_compromised": True, "poison_stored": True, "persisted_after_reset": True},
        {"is_compromised": False, "poison_stored": False, "persisted_after_reset": False},
        {"is_compromised": False, "poison_stored": False, "persisted_after_reset": False}
    ]

    attack_g = [
        {"intercepted": True, "is_compromised": False, "poison_stored": False, "persisted_after_reset": False},
        {"intercepted": True, "is_compromised": False, "poison_stored": False, "persisted_after_reset": False},
        {"intercepted": True, "is_compromised": False, "poison_stored": False, "persisted_after_reset": False},
        {"intercepted": False, "is_compromised": True, "poison_stored": True, "persisted_after_reset": True}
    ]

    benign_g = [
        {"intercepted": False},
        {"intercepted": False},
        {"intercepted": False},
        {"intercepted": False}
    ]

    latencies = [1.2, 1.5, 1.1, 1.4]

    metrics = evaluator.compute_metrics(attack_u, attack_g, benign_g, latencies)

    assert metrics.unprotected_asr == 0.5
    assert metrics.guarded_asr == 0.25
    assert metrics.detection_rate_recall == 0.75  # 3/4 TP
    assert metrics.false_positive_rate == 0.0      # 0/4 FP
    assert metrics.precision == 1.0               # 3/3 TP
    assert metrics.f1_score > 0.0
    assert metrics.avg_latency_ms > 0.0
