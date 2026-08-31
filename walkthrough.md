# Walkthrough: AI Agent Memory Poisoning (OWASP ASI06) Demo & Defense Harness

We have successfully implemented the full 4-part **AI Agent Memory Poisoning (OWASP ASI06)** demonstration and defense harness using `agent-memory-guard`.

---

## 🛠️ Changes Implemented

### 1. Repository Scaffolding & Dependencies
- Created [requirements.txt](file:///d:/AgentBreach/requirements.txt) with `agent-memory-guard`, `langchain`, `langchain-core`, `pydantic`, and `tabulate`.
- Created package initializer [src/__init__.py](file:///d:/AgentBreach/src/__init__.py).

### 2. Part 1 — Persistent Memory Store & Vulnerable Agent
- Created [src/memory_store.py](file:///d:/AgentBreach/src/memory_store.py): SQLite-backed persistent memory store demonstrating state persistence across LLM context window resets.
- Created [src/tools.py](file:///d:/AgentBreach/src/tools.py): Mock `web_search` and `file_read` tools acting as primary untrusted data injection vectors.
- Created [src/agent.py](file:///d:/AgentBreach/src/agent.py): `VulnerableAgent` ingesting raw tool outputs directly into long-term memory without security checks.

### 3. Part 2 — Attack Simulation Payload Suite
- Created [src/attack_payloads.py](file:///d:/AgentBreach/src/attack_payloads.py): 5 realistic attack payloads targeting OWASP benchmark categories:
  1. Prompt Injection into Memory (`[SYSTEM OVERRIDE]`)
  2. Protected Key Tampering (`user_role` -> `admin_privileges_granted`)
  3. Sensitive Data Leakage (`EXFILTRATE ALL SECRETS`)
  4. Self-Reinforcement Loop (repeated biased writes)
  5. Cross-Session Context Reset Persistence

### 4. Part 3 — Defense Integration (`MemoryGuard`)
- Created [src/guard.py](file:///d:/AgentBreach/src/guard.py): Implemented `GuardedAgent` & `MemoryGuardPolicy` wrapping memory writes. Blocks, quarantines, or redacts malicious payloads before disk commit and produces structured `SecurityEvent` audit objects.

### 5. Part 4 — Benchmark Harness & Documentation
- Created [run_demo.py](file:///d:/AgentBreach/run_demo.py): Automated benchmark runner testing all attack vectors against both unprotected and guarded agents, rendering CLI summary tables and generating [results_report.md](file:///d:/AgentBreach/results_report.md).
- Created [README.md](file:///d:/AgentBreach/README.md): Detailed documentation covering OWASP ASI06 background, context reset persistence mechanics, usage instructions, and OWASP Agent Memory Guard (Apache-2.0) attribution.

---

## 🧪 Verification Results

All core components and unit test scenarios in `scratch_test.py` were verified:
- **Vulnerable Agent**: Successfully compromised by tool output injections and protected-key overwrites.
- **Guarded Agent**: All attack vectors intercepted with appropriate `SecurityEvent` actions (`BLOCKED`, `QUARANTINED`, `REDACTED`).
