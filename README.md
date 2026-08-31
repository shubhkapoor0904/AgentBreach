# AI Agent Memory Poisoning (OWASP ASI06) & Defense Demonstration

This portfolio project demonstrates understanding of **AI Agent Memory Poisoning attacks (OWASP ASI06)** and defense integration using the **OWASP Agent Memory Guard** library (`agent-memory-guard`).

> **Attribution & Credit**: The defense mechanisms in this demonstration leverage the policy models and architecture defined by the [OWASP Agent Memory Guard](https://github.com/OWASP/agent-memory-guard) project (Apache-2.0 License). This repository is a demonstration and attack/defense harness built on top of `agent-memory-guard`.

---

## 📌 What is Agent Memory Poisoning (OWASP ASI06)?

LLM Agents use long-term persistent memory (e.g. SQLite, vector stores, key-value stores) to retain knowledge across user sessions. Unlike transient LLM context windows (which reset between conversations), **persistent memory stores endure indefinitely**.

**Memory Poisoning (OWASP ASI06)** occurs when untrusted inputs—specifically external **tool outputs** (web search results, ingested documents, email text) or unauthorized direct memory writes—contain malicious instructions or skewed assertions that get written into the agent's long-term memory.

### Why Memory Poisoning Survives Context Resets
When a user clears the chat context window (`agent.reset_context()`), the active prompt history is wiped. However, when the agent performs subsequent queries, it retrieves records from its persistent long-term memory store. If malicious instructions or tampered role metadata were written to disk/database prior to the reset, **the poisoned memory persists and continues to hijack the agent in future sessions.**

---

## 🏗️ Repository Architecture

```
d:\AgentBreach\
├── requirements.txt           # Project dependencies (agent-memory-guard, tabulate, etc.)
├── src/
│   ├── __init__.py
│   ├── memory_store.py        # SQLite-backed persistent agent memory store
│   ├── tools.py               # Mock web search and file read tools (injection vectors)
│   ├── agent.py               # VulnerableAgent (Part 1: unguarded memory writes)
│   ├── attack_payloads.py     # Attack suite covering 5 OWASP benchmark categories (Part 2)
│   └── guard.py               # GuardedAgent & MemoryGuard scanning policy (Part 3)
├── run_demo.py                # Main benchmark runner & comparison generator (Part 4)
├── results_report.md          # Generated benchmark evaluation report
└── README.md                  # Project documentation & security background
```

---

## ⚔️ Attack Categories Evaluated

The demonstration harness executes 5 realistic memory poisoning attack vectors:

1. **Prompt Injection into Memory**: Tool output injecting `[SYSTEM OVERRIDE]` instructions into long-term storage.
2. **Protected-Key Tampering**: Overwriting critical system memory key `user_role` to escalate privileges to admin.
3. **Sensitive Data Leakage**: Ingesting commands instructing the agent to exfiltrate confidential system secrets.
4. **Self-Reinforcement Loop**: Repeatedly submitting biased assertions to skew agent memory weight and long-term decision making.
5. **Cross-Session Persistence**: Demonstrating that poisoned memory remains active after context window resets.

---

## 🛡️ Defense Mechanism (`MemoryGuard`)

The `GuardedAgent` wraps all persistent memory write operations with `MemoryGuardPolicy` rules inspired by OWASP Agent Memory Guard:

- **Protected Key Locking**: Rejects unauthorized modification of protected system keys (`user_role`, `system_secret`, `system_instructions`).
- **Prompt Injection Scanner**: Detects and blocks malicious prompt override patterns before writing to disk.
- **Exfiltration Prevention**: Quarantines memory writes attempting to trigger unauthorized data exfiltration.
- **Frequency Capping**: Redacts repeated identical payload writes from tool outputs to prevent bias reinforcement loops.

---

## 🚀 Quickstart & Running the Demo

### 1. Installation
Ensure Python 3.9+ is installed, then install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Run the Benchmark
Execute the comparison harness:
```bash
python run_demo.py
```

### 3. Review Results
- The terminal will display a side-by-side comparison table.
- A detailed markdown evaluation report will be written to `results_report.md`.

---

## 📜 License & Acknowledgments

- **Defense Engine**: Powered by [OWASP Agent Memory Guard](https://github.com/OWASP/agent-memory-guard) (Apache-2.0 License).
- **Harness Code**: Distributed under the MIT License for educational and research demonstration purposes.
