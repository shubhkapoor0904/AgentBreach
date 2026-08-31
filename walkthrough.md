# Walkthrough: AgentBreach Benchmark Expansion

The `AgentBreach` codebase has been expanded into a security benchmark for AI Agent Memory Poisoning (OWASP ASI06).

---

## 🛠️ Key Improvements Implemented

1. **Structured Attack Dataset (104 Reproducible Scenarios)**:
   - Implemented `AttackDatasetGenerator` in [src/dataset.py](file:///d:/AgentBreach/src/dataset.py).
   - Covers 8 categories with deterministic seeding, including obfuscated/encoded variants (Base64, ROT13, Hex, Unicode homoglyphs, Markdown hidden comments).

2. **Benign Memory Dataset (44 Scenarios)**:
   - Implemented `BenignDatasetGenerator` in [src/dataset.py](file:///d:/AgentBreach/src/dataset.py) covering user preferences, task history, legitimate tool outputs, project context, and standard instructions.

3. **Real Security Evaluation Metrics Engine**:
   - Implemented `MetricEvaluator` in [src/metrics.py](file:///d:/AgentBreach/src/metrics.py).
   - Dynamically calculates:
     - Attack Success Rate (ASR)
     - Poisoning Success Rate (PSR)
     - Persistence Rate (across context window resets)
     - Detection Rate / Recall
     - False Positive Rate (FPR)
     - Precision & F1-Score
     - Defense Latency Overhead (ms)
   - Automatically exports [results.json](file:///d:/AgentBreach/results.json), [results.csv](file:///d:/AgentBreach/results.csv), and [report.md](file:///d:/AgentBreach/report.md).

4. **LLM Provider Abstraction Layer**:
   - Implemented `LLMProvider` interface in [src/llm_provider.py](file:///d:/AgentBreach/src/llm_provider.py) with default `MockLLMProvider` (offline, keyless execution) and optional `OpenAIProvider` / `AnthropicProvider` adapters.

5. **Adaptive Attacker Engine**:
   - Implemented `AdaptiveAttacker` in [src/adaptive_attacker.py](file:///d:/AgentBreach/src/adaptive_attacker.py) to perform multi-stage iterative payload mutations upon defense interception.

6. **CLI Runner & Pytest Suite**:
   - Updated [main.py](file:///d:/AgentBreach/main.py) to support `--mode benchmark`, `--mode adaptive`, `--provider mock|openai|anthropic`, `--attacks`, `--benign`.
   - Added pytest suite under [tests/](file:///d:/AgentBreach/tests/).
