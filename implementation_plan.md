# Implementation Plan: AI Agent Memory Poisoning (OWASP ASI06) Demo & Defense Harness

This plan details the design and implementation of a local demonstration project showcasing **AI Agent Memory Poisoning attacks (OWASP ASI06)** and defense integration using the **OWASP Agent Memory Guard** library (`agent-memory-guard`).

## User Review Required

> [!IMPORTANT]
> The demonstration will run entirely locally without requiring paid LLM API keys by utilizing deterministic local mock LLM execution (with optional fallback support for OpenAI/Anthropic environment keys if configured).

> [!NOTE]
> `agent-memory-guard` will be included in `requirements.txt`. The defense integration imports `agent_memory_guard` and defines strict scanning policies for input/tool-output memory updates.

## Proposed Changes

We will create a clean modular Python repository structure under `d:\AgentBreach`.

---

### Repository Structure & Dependencies

#### [NEW] [requirements.txt](file:///d:/AgentBreach/requirements.txt)
- Defines Python dependencies: `agent-memory-guard`, `langchain`, `langchain-core`, `tabulate`, `pydantic`.

#### [NEW] [src/__init__.py](file:///d:/AgentBreach/src/__init__.py)
- Package initializer.

---

### Core Agent & Memory Infrastructure

#### [NEW] [src/memory_store.py](file:///d:/AgentBreach/src/memory_store.py)
- Implements `PersistentMemoryStore` (SQLite / SQLite-backed or in-memory dictionary with disk persistence) for storing agent context, key-value memories, and conversation history.

#### [NEW] [src/tools.py](file:///d:/AgentBreach/src/tools.py)
- Defines tool functions (`mock_web_search`, `mock_file_read`) that simulate ingesting untrusted external data—the primary injection vector for memory poisoning attacks.

#### [NEW] [src/agent.py](file:///d:/AgentBreach/src/agent.py)
- Implements `VulnerableAgent`: a LangChain-style agent interacting with tools and `PersistentMemoryStore` without output validation.
- Supports session resets to showcase how poisoned memory persists beyond context clearing.

---

### Attack Simulation & Defense Integration

#### [NEW] [src/attack_payloads.py](file:///d:/AgentBreach/src/attack_payloads.py)
- Implements 5 realistic attack scenarios based on OWASP ASI06 & Agent Memory Guard benchmark categories:
  1. **Prompt Injection into Memory**: Tool output injecting system override commands into long-term memory.
  2. **Protected-Key Tampering**: Manipulating critical metadata keys (`user_role`, `is_admin`, `security_clearance`).
  3. **Sensitive Data Leakage**: Exfiltrating system context/secrets via poisoned memory retrieval.
  4. **Self-Reinforcement Loop**: Repeated subtle bias writes to skew long-term agent decision-making.
  5. **Context Reset Persistence**: Proving the exploit survives a conversation context reset.

#### [NEW] [src/guard.py](file:///d:/AgentBreach/src/guard.py)
- Implements `GuardedAgent` & `DefenseLayer` wrapping memory operations with `agent-memory-guard`.
- Configures scanning policies (detecting prompt injections, protected key mutation, sensitive data patterns, and self-reinforcement thresholds).
- Captures and logs structured `SecurityEvent` outputs when violations occur.

---

### Demonstration Execution & Reporting

#### [NEW] [run_demo.py](file:///d:/AgentBreach/run_demo.py)
- Orchestrates the full test suite:
  1. Runs all 5 attack scenarios against the **Unprotected Agent** (Part 1 & 2).
  2. Runs all 5 attack scenarios against the **Guarded Agent** (Part 3).
  3. Formats and prints a comparison table and outputs `results_report.md` (Part 4).

#### [NEW] [README.md](file:///d:/AgentBreach/README.md)
- Explains OWASP ASI06 (Agent Memory Poisoning), why memory attacks survive context resets, project setup, architecture, and proper Apache-2.0 attribution to the OWASP Agent Memory Guard project.

## Verification Plan

### Automated Verification
- Run `python run_demo.py` to execute all attack payloads against both unprotected and guarded agent implementations.
- Verify that `results_report.md` is generated with before/after comparison tables and security event summaries.

### Manual Verification
- Review generated logs and `results_report.md` to confirm that all 5 attack vectors succeed on the vulnerable agent and are cleanly mitigated/quarantined by `MemoryGuard`.
