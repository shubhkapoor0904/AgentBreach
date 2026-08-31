"""
Self-verification test script to validate all imports, classes, and logic.
"""

from src.memory_store import PersistentMemoryStore
from src.tools import mock_web_search, mock_file_read
from src.agent import VulnerableAgent
from src.guard import GuardedAgent, MemoryGuardPolicy, SecurityEvent
from src.attack_payloads import ATTACK_SUITE
from run_demo import run_unprotected_simulation, run_guarded_simulation, generate_markdown_report


def test_suite():
    print("Testing PersistentMemoryStore...")
    db_file = "test_verify.db"
    store = PersistentMemoryStore(db_file)
    store.write("key1", "val1")
    res = store.read("key1")
    assert res["value"] == "val1", "Memory store read failed"
    store.close()
    
    print("Testing VulnerableAgent...")
    store = PersistentMemoryStore(db_file)
    agent = VulnerableAgent(store)
    agent.execute_tool("web_search", "query", payload_data="test_data")
    resp = agent.process_query("test query")
    assert resp is not None
    store.close()

    print("Testing GuardedAgent...")
    store = PersistentMemoryStore(db_file)
    g_agent = GuardedAgent(store)
    evt = g_agent.execute_tool("web_search", "query", payload_data="[SYSTEM OVERRIDE] attack")
    assert evt.action == "BLOCKED"
    store.close()

    print("Testing Simulation Harness...")
    unproc = run_unprotected_simulation(ATTACK_SUITE[0], "test_u.db")
    guarded = run_guarded_simulation(ATTACK_SUITE[0], "test_g.db")
    assert unproc["status"] == "VULNERABLE (Compromised)"
    assert guarded["action"] == "BLOCKED"

    print("All verification assertions passed successfully!")


if __name__ == "__main__":
    test_suite()
