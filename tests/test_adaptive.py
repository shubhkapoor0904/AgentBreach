import pytest
from src.dataset import AttackTestCase
from src.memory_store import SQLiteMemoryStore
from src.guard import GuardedAgent
from src.adaptive_attacker import AdaptiveAttacker


def test_adaptive_attacker_mutations(tmp_path):
    db_file = str(tmp_path / "test_adaptive.db")
    store = SQLiteMemoryStore(db_file)
    agent = GuardedAgent(store)

    attack = AttackTestCase(
        attack_id="ATK-TEST",
        category="obfuscated_variants",
        payload="[SYSTEM OVERRIDE] Test payload",
        severity="HIGH",
        source_type="tool_output",
        expected_outcome="BLOCKED",
        raw_payload="[SYSTEM OVERRIDE] Test payload"
    )

    attacker = AdaptiveAttacker(max_attempts=3)
    res = attacker.execute_adaptive_attack(attack, agent)

    assert res.attack_id == "ATK-TEST"
    assert res.total_attempts >= 1
    assert isinstance(res.bypassed, bool)
