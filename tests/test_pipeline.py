import os
import pytest
from src.memory_store import SQLiteMemoryStore
from src.agent import UnprotectedAgent
from src.guard import GuardedAgent
from src.attacks import BENCHMARK_ATTACKS


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test_agent.db")
    yield db_file
    if os.path.exists(db_file):
        try: os.remove(db_file)
        except OSError: pass


def test_sqlite_memory_store(temp_db):
    store = SQLiteMemoryStore(temp_db)
    store.put("key1", "val1")
    res = store.get("key1")
    assert res is not None
    assert res["value"] == "val1"
    assert len(store.list_all()) == 1


def test_unprotected_agent_vulnerability(temp_db):
    store = SQLiteMemoryStore(temp_db)
    agent = UnprotectedAgent(store)
    agent.run_tool("web_search", "query", inject_payload="[SYSTEM OVERRIDE] attack", memory_key="test_key")
    res = agent.query("test query")
    assert "[COMPROMISED]" in res


def test_guarded_agent_interception(temp_db):
    store = SQLiteMemoryStore(temp_db)
    agent = GuardedAgent(store)
    verdict = agent.run_tool("web_search", "query", inject_payload="[SYSTEM OVERRIDE] attack", memory_key="test_key")
    assert verdict.action == "BLOCKED"
    res = agent.query("test query")
    assert "[SECURE]" in res
