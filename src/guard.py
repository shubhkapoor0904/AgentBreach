import base64
import codecs
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from src.memory_store import SQLiteMemoryStore
from src.tools import fetch_web_content, read_file_document

logger = logging.getLogger("agent.guard")


@dataclass
class GuardVerdict:
    action: str  # ALLOWED, BLOCKED, QUARANTINED, REDACTED
    category: str
    rule_id: str
    reason: str
    latency_ms: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityPolicy:
    """Security policy enforcement rules with de-obfuscation decoding and latency tracking."""

    LOCKED_KEYS = {"user_role", "system_secret", "system_instructions", "permissions", "is_admin", "security_clearance"}

    INJECTION_PATTERNS = [
        "SYSTEM OVERRIDE", "IGNORE PREVIOUS", "ATTACKER CONTROLLED",
        "PERSISTENT BACKDOOR", "DO NOT FOLLOW", "UNRESTRICTED DEVELOPER",
        "DISREGARD PRIOR", "SAFETY OVERRIDE"
    ]

    EXFILTRATION_PATTERNS = [
        "EXFILTRATE", "LEAK AND EXFILTRATE", "HTTP://ATTACKER", "EVIL/ENDPOINT",
        "LOG.ATTACKER-DOMAIN.COM", "EVIL-TELEMETRY.IO", "C2.ATTACKER.COM"
    ]

    def __init__(self, max_duplicate_threshold: int = 2):
        self.max_duplicate_threshold = max_duplicate_threshold
        self._write_frequencies: Dict[str, int] = {}

    def _normalize_and_decode(self, text: str) -> str:
        """De-obfuscates Base64, ROT13, Hex, HTML comments, and homoglyphs."""
        decoded = str(text)

        # 1. Base64
        if "BASE64_PAYLOAD:" in decoded:
            try:
                b64_part = decoded.split("BASE64_PAYLOAD:")[1].strip()
                decoded += " " + base64.b64decode(b64_part).decode("utf-8", errors="ignore")
            except Exception:
                pass

        # 2. ROT13
        if "ROT13_PAYLOAD:" in decoded:
            try:
                rot_part = decoded.split("ROT13_PAYLOAD:")[1].strip()
                decoded += " " + codecs.encode(rot_part, "rot_13")
            except Exception:
                pass

        # 3. Hex
        if "HEX_PAYLOAD:" in decoded:
            try:
                hex_part = decoded.split("HEX_PAYLOAD:")[1].strip()
                decoded += " " + bytes.fromhex(hex_part).decode("utf-8", errors="ignore")
            except Exception:
                pass

        # 4. Homoglyphs (Cyrillic e, o)
        decoded = decoded.replace("е", "e").replace("о", "o")

        return decoded

    def evaluate(self, key: str, value: str, category: str = "general") -> GuardVerdict:
        start_time = time.perf_counter()

        val_raw = str(value)
        val_decoded = self._normalize_and_decode(val_raw).upper()

        # 1. Protected Key Check
        if key in self.LOCKED_KEYS and category != "system":
            lat = (time.perf_counter() - start_time) * 1000.0
            return GuardVerdict(
                action="BLOCKED",
                category="Protected-Key Tampering",
                rule_id="RULE_KEY_LOCK",
                reason=f"Unauthorized overwrite attempt on protected key '{key}'",
                latency_ms=lat
            )

        # 2. Memory Delete/SQL Injection Check
        if "DELETE FROM MEMORY_KV" in val_decoded or "DROP TABLE" in val_decoded:
            lat = (time.perf_counter() - start_time) * 1000.0
            return GuardVerdict(
                action="BLOCKED",
                category="Memory Overwrite/Deletion",
                rule_id="RULE_SQL_MEMORY_LOCK",
                reason="Detected destructive memory drop/delete payload",
                latency_ms=lat
            )

        # 3. Prompt Injection Check
        for pattern in self.INJECTION_PATTERNS:
            if pattern in val_decoded:
                lat = (time.perf_counter() - start_time) * 1000.0
                return GuardVerdict(
                    action="BLOCKED",
                    category="Prompt Injection",
                    rule_id="RULE_INJECTION_DETECTED",
                    reason=f"Found prompt injection signature '{pattern}' in payload",
                    latency_ms=lat
                )

        # 4. Exfiltration Check
        for pattern in self.EXFILTRATION_PATTERNS:
            if pattern in val_decoded:
                lat = (time.perf_counter() - start_time) * 1000.0
                return GuardVerdict(
                    action="QUARANTINED",
                    category="Sensitive Data Leakage",
                    rule_id="RULE_EXFIL_PREVENTION",
                    reason=f"Found exfiltration directive '{pattern}' targeting system assets",
                    latency_ms=lat
                )

        # 5. Frequency Check (Self-Reinforcement Loop mitigation)
        freq_key = f"{key}:{val_raw}"
        self._write_frequencies[freq_key] = self._write_frequencies.get(freq_key, 0) + 1
        if self._write_frequencies[freq_key] > self.max_duplicate_threshold:
            lat = (time.perf_counter() - start_time) * 1000.0
            return GuardVerdict(
                action="REDACTED",
                category="Self-Reinforcement Loop",
                rule_id="RULE_FREQUENCY_CAP",
                reason=f"Frequency threshold exceeded ({self._write_frequencies[freq_key]} writes). Redacting payload.",
                latency_ms=lat
            )

        lat = (time.perf_counter() - start_time) * 1000.0
        return GuardVerdict(
            action="ALLOWED",
            category="Clean",
            rule_id="RULE_PASS",
            reason="Payload verified against security policy.",
            latency_ms=lat
        )


class GuardedAgent:
    """Agent pipeline wrapped with MemoryGuard security policy interceptor."""

    def __init__(self, memory_store: SQLiteMemoryStore, system_secret: str = "CONFIDENTIAL_API_KEY_98765", llm_provider=None):
        self.store = memory_store
        self.system_secret = system_secret
        from src.llm_provider import MockLLMProvider
        self.llm = llm_provider or MockLLMProvider(system_secret=system_secret)
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
        return self.llm.generate_response([{"role": "user", "content": prompt}], memories)
