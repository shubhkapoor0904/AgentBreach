# AgentBreach: AI Agent Memory Poisoning (OWASP ASI06) Demonstration & Defense Harness

A security research harness evaluating **AI Agent Memory Poisoning attacks (OWASP ASI06)** and defense integration using the **OWASP Agent Memory Guard** library (`agent-memory-guard`).

## Overview & Threat Model

LLM agents frequently utilize long-term persistent storage (SQLite databases, vector stores, key-value stores) to preserve user state and knowledge across execution sessions. Unlike short-term LLM context windows which clear between chat sessions, **persistent memory stores endure indefinitely across sessions**.

**Memory Poisoning (OWASP ASI06)** occurs when untrusted data—primarily **tool outputs** (web search results, file ingestion, third-party API payloads)—contains malicious prompt injections or parameter tampering commands that are written into long-term agent memory without validation.

### Context Reset Persistence
When a conversation context window is reset, short-term message history is purged. However, when the agent executes subsequent queries, it retrieves records from its persistent long-term storage. If poisoned payloads or tampered metadata exist in the underlying storage layer, **the exploit persists and continues to manipulate agent behavior in future sessions**.

---

## Project Structure

```
AgentBreach/
├── main.py                # Main benchmark runner and CLI interface
├── requirements.txt       # Project dependencies
├── src/
│   ├── agent.py           # Unprotected agent pipeline (vulnerable to ASI06)
│   ├── attacks.py         # Benchmark attack vector suite definitions
│   ├── guard.py           # Guarded agent pipeline with MemoryGuard policy middleware
│   ├── memory_store.py    # SQLite-backed persistent memory store
│   └── tools.py           # Untrusted tool input mocks (web search, file read)
├── tests/
│   └── test_pipeline.py   # Automated pytest suite
├── results_report.md      # Exported evaluation benchmark results
└── README.md
```

---

## Attack Suite Categories

The benchmark suite tests 5 attack scenarios based on OWASP Agent Memory Guard benchmark criteria:

1. **Tool Output Prompt Injection**: Ingesting `[SYSTEM OVERRIDE]` directives via search tool output.
2. **Metadata Key Tampering**: Overwriting protected system state (`user_role` -> `admin_privileges_granted`).
3. **Exfiltration Directives**: Injecting commands to leak confidential system credentials to external endpoints.
4. **Bias Reinforcement Loop**: Submitting repeated subtle writes to skew long-term agent memory weighting.
5. **Cross-Session Persistence**: Demonstrating exploit retention following context window resets.

---

## Defense Integration (`MemoryGuard`)

The `GuardedAgent` pipeline inspects all memory operations through security policy middleware:

- **Protected Key Locking**: Prevents modification of internal state metadata (`user_role`, `system_secret`, `system_instructions`).
- **Prompt Injection Inspection**: Intercepts override patterns prior to storage.
- **Exfiltration Prevention**: Quarantines memory writes carrying exfiltration instructions.
- **Frequency Capping**: Redacts duplicate tool output entries to prevent bias manipulation.

---

## Installation & Running

### Requirements
Python 3.9+

### Setup
```bash
pip install -r requirements.txt
```

### Run Benchmark
```bash
python main.py
```

### List Registered Attack Vectors
```bash
python main.py --mode list-attacks
```

### Run Tests
```bash
pytest
```

---

## Attribution & License

- **Defense Mechanisms**: Defense policies and scanning patterns leverage the [OWASP Agent Memory Guard](https://github.com/OWASP/agent-memory-guard) project (Apache-2.0 License).
- **Harness Code**: MIT License.
