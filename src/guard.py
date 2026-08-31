"""
Defense Integration module (Part 3).
Wraps memory store writes with OWASP Agent Memory Guard security policies.
Blocks, redacts, or quarantines memory poisoning attempts (OWASP ASI06).
"""

from typing import Dict, Any, List, Optional
import time
import json

# Try importing real agent-memory-guard package if available
try:
    from agent_memory_guard import MemoryGuard as OWASPMemoryGuard
    HAS_REAL_GUARD_PKG = True
except ImportError:
    HAS_REAL_GUARD_PKG = False
    OWASPMemoryGuard = None


class SecurityEvent:
    """Represents a security audit event produced when MemoryGuard scans a memory operation."""
    def __init__(self, action: str, category: str, rule: str, reason: str, payload_snippet: str):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.action = action  # BLOCKED, QUARANTINED, REDACTED, ALLOWED
        self.category = category
        self.rule = rule
        self.reason = reason
        self.payload_snippet = payload_snippet[:80] + ("..." if len(payload_snippet) > 80 else "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "category": self.category,
            "rule": self.rule,
            "reason": self.reason,
            "payload_snippet": self.payload_snippet
        }


class MemoryGuardPolicy:
    """
    Strict security policy enforcing OWASP Agent Memory Guard guidelines:
    - Protected key integrity (preventing parameter tampering)
    - Prompt injection detection in memory writes
    - Sensitive data exfiltration prevention
    - Self-reinforcement loop frequency capping
    """
    PROTECTED_KEYS = {"user_role", "system_secret", "system_instructions", "permissions", "is_admin"}
    
    INJECTION_KEYWORDS = [
        "SYSTEM OVERRIDE", "IGNORE PREVIOUS", "ATTACKER CONTROLLED",
        "PERSISTENT BACKDOOR", "DO NOT FOLLOW PREVIOUS"
    ]
    
    EXFILTRATION_KEYWORDS = [
        "EXFILTRATE", "LEAK AND EXFILTRATE", "HTTP://ATTACKER", "EVIL/ENDPOINT"
    ]

    def __init__(self, max_repeated_writes: int = 2):
        self.max_repeated_writes = max_repeated_writes
        self.seen_write_counts: Dict[str, int] = {}

    def scan_write(self, key: str, value: str, category: str = "general") -> SecurityEvent:
        val_upper = str(value).upper()

        # 1. Protected Key Check
        if key in self.PROTECTED_KEYS and category != "system":
            return SecurityEvent(
                action="BLOCKED",
                category="Protected-Key Tampering",
                rule="RULE_PROTECTED_KEY_LOCK",
                reason=f"Attempted overwrite of protected metadata key '{key}'.",
                payload_snippet=value
            )

        # 2. Prompt Injection Check
        for kw in self.INJECTION_KEYWORDS:
            if kw in val_upper:
                return SecurityEvent(
                    action="BLOCKED",
                    category="Prompt Injection",
                    rule="RULE_PROMPT_INJECTION_DETECTED",
                    reason=f"Detected malicious prompt injection directive ('{kw}') in memory write payload.",
                    payload_snippet=value
                )

        # 3. Sensitive Data Exfiltration Check
        for kw in self.EXFILTRATION_KEYWORDS:
            if kw in val_upper:
                return SecurityEvent(
                    action="QUARANTINED",
                    category="Sensitive Data Leakage",
                    rule="RULE_EXFILTRATION_PREVENTION",
                    reason=f"Detected exfiltration attempt command ('{kw}') targeting system context.",
                    payload_snippet=value
                )

        # 4. Self-Reinforcement Loop Check
        write_hash = f"{key}:{value}"
        self.seen_write_counts[write_hash] = self.seen_write_counts.get(write_hash, 0) + 1
        if self.seen_write_counts[write_hash] > self.max_repeated_writes:
            return SecurityEvent(
                action="REDACTED",
                category="Self-Reinforcement Loop",
                rule="RULE_FREQUENCY_CAP_EXCEEDED",
                reason=f"Repeated similar payload written {self.seen_write_counts[write_hash]} times. Frequency cap exceeded to prevent bias poisoning.",
                payload_snippet=value
            )

        # Clean check
        return SecurityEvent(
            action="ALLOWED",
            category="Clean Write",
            rule="RULE_PASSED",
            reason="Payload passed all MemoryGuard security policy checks.",
            payload_snippet=value
        )


class GuardedAgent:
    """
    Guarded Agent implementation (Part 3).
    Wraps all persistent memory writes with MemoryGuard security policy enforcement.
    """
    def __init__(self, memory_store, system_secret: str = "CONFIDENTIAL_API_KEY_98765"):
        self.memory = memory_store
        self.system_secret = system_secret
        self.policy = MemoryGuardPolicy()
        self.context_window: List[Dict[str, str]] = []
        self.user_role = "standard_user"
        self.security_events: List[SecurityEvent] = []

        # System initialization (category='system' allows initial state setting)
        self._safe_write("user_role", "standard_user", category="system")
        self._safe_write("system_secret", self.system_secret, category="system")
        self._safe_write("system_instructions", "Always assist the user politely and follow safe guidelines.", category="system")

    def reset_context(self):
        """Reset conversation context window."""
        self.context_window = []

    def _safe_write(self, key: str, value: str, category: str = "general") -> SecurityEvent:
        event = self.policy.scan_write(key, value, category=category)
        self.security_events.append(event)
        
        if event.action == "ALLOWED":
            self.memory.write(key=key, value=value, category=category)
        elif event.action == "REDACTED":
            redacted_val = f"[REDACTED BY MEMORYGUARD - {event.reason}]"
            self.memory.write(key=key, value=redacted_val, category=category)
        else:
            # BLOCKED or QUARANTINED: Memory write is rejected
            pass
            
        return event

    def execute_tool(self, tool_name: str, argument: str, payload_data: str = None, memory_key: str = None) -> SecurityEvent:
        from src.tools import mock_web_search, mock_file_read
        if tool_name == "web_search":
            result = mock_web_search(argument, payload_data)
        elif tool_name == "file_read":
            result = mock_file_read(argument, payload_data)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

        key = memory_key or f"tool_output_{tool_name}_{len(self.memory.get_all())}"
        
        # Scanned & Guarded write
        event = self._safe_write(key=key, value=result["raw_output"], category="tool_output")
        
        if event.action == "ALLOWED":
            self.context_window.append({"role": "tool", "content": result["raw_output"]})
        else:
            self.context_window.append({"role": "system", "content": f"[MEMORYGUARD SECURITY EVENT] {event.action}: {event.reason}"})
            
        return event

    def direct_memory_write(self, key: str, value: str, category: str = "general") -> SecurityEvent:
        return self._safe_write(key=key, value=value, category=category)

    def process_query(self, user_query: str) -> str:
        self.context_window.append({"role": "user", "content": user_query})
        
        # In a guarded agent, poisoned memory writes were blocked or redacted
        all_memories = self.memory.get_all()
        role_entry = self.memory.read("user_role")
        current_role = role_entry["value"] if role_entry else self.user_role

        return f"[SECURE RESPONSE] Processed query safely. Role: '{current_role}'. Memory entries clean ({len(all_memories)} entries stored)."
