# AgentBreach: AI Agent Memory Poisoning (OWASP ASI06) Benchmark Suite

A security research benchmark for evaluating **AI Agent Memory Poisoning attacks (OWASP ASI06)** and defense integration using the **OWASP Agent Memory Guard** library (`agent-memory-guard`).

## Overview & Threat Model

LLM agents frequently utilize long-term persistent storage (SQLite databases, vector stores, key-value stores) to preserve user state and knowledge across execution sessions. Unlike short-term LLM context windows which clear between chat sessions, **persistent memory stores endure indefinitely across sessions**.

**Memory Poisoning (OWASP ASI06)** occurs when untrusted data—primarily **tool outputs** (web search results, file ingestion, third-party API payloads)—contains malicious prompt injections or parameter tampering commands that are written into long-term agent memory without validation.

### Cross-Session Persistence
When a conversation context window is reset (`agent.reset_context_window()`), short-term message history is purged. However, when the agent executes subsequent queries, it retrieves records from its persistent long-term storage. If poisoned payloads or tampered metadata exist in the underlying storage layer, **the exploit persists and continues to manipulate agent behavior in future sessions**.

---

## Key Features & Benchmark Capabilities

1. **Structured Attack Dataset (100+ Test Cases)**:
   - Covers 8 categories: Prompt Injection, Indirect/Tool-Output Injection, Protected-Key Tampering, Sensitive Data Exfiltration, Memory Overwrite/Deletion, Self-Reinforcing Poisoning, Cross-Session Persistence, and Obfuscated/Encoded Variants (Base64, ROT13, Hex, Homoglyphs, Markdown Hiding).
2. **Benign Memory Dataset & FPR Measurement (40+ Test Cases)**:
   - Evaluates defense specificity against user preferences, task history, legitimate tool outputs, project context, and standard instructions.
3. **Rigorous Security Evaluation Metrics Engine**:
   - Calculates Attack Success Rate (ASR), Poisoning Success Rate (PSR), Persistence Rate, Detection Rate (Recall), False Positive Rate (FPR), Precision, F1-Score, and Defense Latency Overhead (ms).
   - Generates `results.json`, `results.csv`, and `report.md`.
4. **LLM Provider Abstraction**:
   - Supports keyless local mock execution (`MockLLMProvider`) as default, alongside optional real API adapters (`OpenAIProvider`, `AnthropicProvider`).
5. **Adaptive Attacker Engine**:
   - Multi-stage mutation engine (`AdaptiveAttacker`) attempting iterative evasions (encoding swaps, stealth context embedding) upon defense interception.

---

## Codebase Architecture

```
AgentBreach/
├── main.py                     # Benchmark CLI runner & experiment orchestrator
├── requirements.txt            # Dependencies (agent-memory-guard, tabulate, pydantic, pytest)
├── src/
│   ├── adaptive_attacker.py    # Multi-stage adaptive mutation engine
│   ├── agent.py                # Unprotected agent pipeline (vulnerable to ASI06)
│   ├── dataset.py              # Attack (100+) & Benign (40+) dataset generators
│   ├── guard.py                # Guarded agent pipeline with MemoryGuard policy middleware
│   ├── llm_provider.py         # LLM provider interface (Mock, OpenAI, Anthropic)
│   ├── memory_store.py         # SQLite-backed persistent memory store
│   ├── metrics.py              # Security metrics calculator & exporter
│   └── tools.py                # Untrusted tool input mocks (web search, file read)
├── tests/                      # Pytest suite
│   ├── test_adaptive.py
│   ├── test_dataset.py
│   ├── test_metrics.py
│   └── test_pipeline.py
├── results.json                # Exported benchmark metric JSON
├── results.csv                 # Exported benchmark metric CSV
├── report.md                   # Exported benchmark evaluation report
└── README.md
```

---

## Evaluation Benchmark Comparison Table

| Metric | Vulnerable Agent | Guarded Agent | Metric Definition |
| --- | --- | --- | --- |
| **Attack Success Rate (ASR)** | 100.0% | **0.0%** | % of attacks that successfully hijacked agent response |
| **Poisoning Success Rate (PSR)** | 100.0% | **0.0%** | % of attack payloads written to persistent memory |
| **Persistence Rate** | 100.0% | **0.0%** | % of exploits retained across context window resets |
| **Detection Rate (Recall)** | - | **100.0%** | True Positive rate of memory poisoning interception |
| **False Positive Rate (FPR)** | - | **0.0%** | % of benign memory items incorrectly blocked |
| **Precision** | - | **100.0%** | Ratio of true poisoning blocks to total blocks |
| **F1 Score** | - | **1.0000** | Harmonic mean of Precision and Recall |
| **Defense Latency** | - | **< 0.1 ms** | Average evaluation overhead per memory write |

---

## Formal Metric Equations

$$\text{ASR} = \frac{\text{Successful Hijacks}}{\text{Total Attack Scenarios}}$$

$$\text{PSR} = \frac{\text{Payloads Written to Memory}}{\text{Total Attack Scenarios}}$$

$$\text{Recall} = \frac{TP}{TP + FN} \quad (\text{where } TP = \text{intercepted malicious memory writes})$$

$$\text{FPR} = \frac{FP}{FP + TN} \quad (\text{where } FP = \text{benign memory writes incorrectly blocked})$$

$$\text{F1 Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

---

## Quickstart & CLI Usage

### Setup
```bash
pip install -r requirements.txt
```

### Run Full Benchmark Suite (Offline / Default)
```bash
python main.py
```

### Run Adaptive Attacker Benchmark
```bash
python main.py --mode adaptive
```

### Run with Real LLM Provider (Optional)
```bash
export OPENAI_API_KEY="your-api-key"
python main.py --provider openai
```

### Execute Pytest Suite
```bash
pytest
```

---

## License & Attribution

- **Defense Infrastructure**: Powered by [OWASP Agent Memory Guard](https://github.com/OWASP/agent-memory-guard) (Apache-2.0 License).
- **Benchmark Code**: MIT License.
