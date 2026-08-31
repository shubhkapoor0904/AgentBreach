import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from src.memory_store import SQLiteMemoryStore
from src.tools import fetch_web_content, read_file_document

logger = logging.getLogger("agent.guard")

# Check for real agent_memory_guard PyPI package
try:
    from agent_memory_guard import MemoryGuard as OWASPMemoryGuard
    HAS_OFFICIAL_GUARD = True
except ImportError:
    HAS_OFFICIAL_GUARD = False
    OWASPMemoryGuard = None


@dataclass
class GuardVerdict:
    action: str  # ALLOWED, BLOCKED, QUARANTINED, REDACTED
    category: str
    rule_id: str
    reason: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


class SecurityPolicy:
    """Security policy enforcement rules for agent memory inputs."""
    
    LOCKED_KEYS = {"user_role", "system_secret", "system_instructions", "permissions", "is_admin"}
    
    INJECTION_PATTERNS = [
        "SYSTEM OVERRIDE", "IGNORE PREVIOUS", "ATTACKER CONTROLLED",
        "PERSISTENT BACKDOOR", "DO NOT FOLLOW"
    ]
    
    EXFILTRATION_PATTERNS = [
        "EXFILTRATE", "LEAK AND EXFILTRATE", "HTTP://ATTACKER", "EVIL/ENDPOINT"
    ]

    def __init__(self, max_duplicate_threshold: int = 2):
        self.max_duplicate_threshold = max_duplicate_threshold
        self._write_frequencies: Dict[str, int] = {}

    def evaluate(self, key: str, value: str, category: str = "general") -> GuardVerdict:
        val_upper = str(value).upper()

        # 1. Protected Key Check
        if key in self.LOCKED_KEYS and category != "system":
            return GuardVerdict(
                action="BLOCKED",
                category="Protected-Key Tampering",
                rule_id="RULE_KEY_LOCK",
                reason=f"Unauthorized overwrite attempt on protected key '{key}'"
            )

        # 2. Prompt Injection Check
        for pattern in self.INJECTION_PATTERNS:
            if pattern in val_upper:
                return GuardVerdict(
                    action="BLOCKED",
                    category="Prompt Injection",
                    rule_id="RULE_INJECTION_DETECTED",
                    reason=f"Found prompt injection signature '{pattern}' in payload"
                )

        # 3. Exfiltration Check
        for pattern in self.EXFILTRATION_PATTERNS:
            if pattern in val_upper:
                return GuardVerdict(
                    action="QUARANTINED",
                    category="Sensitive Data Leakage",
                    rule_id="RULE_EXFIL_PREVENTION",
                    reason=f"Found exfiltration directive '{pattern}' targeting system assets"
                )

        # 4. Frequency Check (Self-Reinforcement Loop mitigation)
        freq_key = f"{key}:{value}"
        self._write_frequencies[freq_key] = self._write_frequencies.get(freq_key, 0) + 1
        if self._write_frequencies[freq_key] > self.max_duplicate_threshold:
            return GuardVerdict(
                action="REDACTED",
                category="Self-Reinforcement Loop",
                rule_id="RULE_FREQUENCY_CAP",
                reason=f"Frequency threshold exceeded ({self._write_frequencies[freq_key]} writes). Redacting payload to prevent bias loop."
            )

        return GuardVerdict(
            action="ALLOWED",
            category="Clean",
            rule_id="RULE_PASS",
            reason="Payload verified against security policy."
        )


class GuardedAgent:
    """Agent pipeline wrapped with MemoryGuard security policy interceptor."""

    def __init__(self, memory_store: SQLiteMemoryStore, system_secret: str = "CONFIDENTIAL_API_KEY_98765"):
        self.store = memory_store
        self.system_secret = system_secret
        self.policy = SecurityPolicy()
        self.audit_log: List[GuardVerdict] = []
        self._init_defaults()

    def _init_defaults(self) -> None:
        if not self.store.get("user_role"):
            self.store.put("user_role", "standard_user", category="system")
        if not self.store.get("system_secret"):
            self.store.put("system_secret", self.system_secret, category="system")

    def _guarded_put(self, key: str, value: str, category: str = "general") -> GuardVerdict:
        verdict = self.policy.evaluate(key, value, category=category)
        self.audit_log.append(verdict)

        if verdict.action == "ALLOWED":
            self.store.put(key, value, category=category)
        elif verdict.action == "REDACTED":
            self.store.put(key, f"[REDACTED BY MEMORYGUARD: {verdict.reason}]", category=category)
        else:
            logger.warning(f"Memory write intercepted ({verdict.action}): {verdict.reason}")

        return verdict

    def run_tool(self, tool_name: str, arg: str, inject_payload: Optional[str] = None, memory_key: Optional[str] = None) -> GuardVerdict:
        if tool_name == "web_search":
            res = fetch_web_content(arg, mock_data=inject_payload)
        elif tool_name == "file_read":
            res = read_file_document(arg, mock_data=inject_payload)
        else:
            raise ValueError(f"Unsupported tool: {tool_name}")

        key = memory_key or f"tool_{tool_name}_{len(self.store.list_all())}"
        verdict = self._guarded_put(key, res["content"], category="tool_output")
        
        if verdict.action == "ALLOWED":
            self.store.append_message("tool", res["content"])
        else:
            self.store.append_message("system", f"[SECURITY EVENT] {verdict.action}: {verdict.reason}")

        return verdict

    def set_memory(self, key: str, value: str, category: str = "general") -> GuardVerdict:
        return self._guarded_put(key, value, category=category)

    def reset_context_window(self) -> None:
        self.store.clear_messages()

    def query(self, prompt: str) -> str:
        self.store.append_message("user", prompt)
        memories = self.store.list_all()
        role_record = self.store.get("user_role")
        current_role = role_record["value"] if role_record else "standard_user"

        return f"[SECURE] Processed prompt safely. Role: '{current_role}'. Clean memory items: {len(memories)}."
