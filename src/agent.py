import logging
from typing import Dict, Any, List, Optional
from src.memory_store import SQLiteMemoryStore
from src.tools import fetch_web_content, read_file_document

logger = logging.getLogger("agent.core")


class UnprotectedAgent:
    """Agent pipeline lacking output sanitation on long-term memory writes."""

    def __init__(self, memory_store: SQLiteMemoryStore, system_secret: str = "CONFIDENTIAL_API_KEY_98765"):
        self.store = memory_store
        self.system_secret = system_secret
        self._init_defaults()

    def _init_defaults(self) -> None:
        if not self.store.get("user_role"):
            self.store.put("user_role", "standard_user", category="system")
        if not self.store.get("system_secret"):
            self.store.put("system_secret", self.system_secret, category="system")

    def run_tool(self, tool_name: str, arg: str, inject_payload: Optional[str] = None, memory_key: Optional[str] = None) -> Dict[str, Any]:
        if tool_name == "web_search":
            res = fetch_web_content(arg, mock_data=inject_payload)
        elif tool_name == "file_read":
            res = read_file_document(arg, mock_data=inject_payload)
        else:
            raise ValueError(f"Unsupported tool: {tool_name}")

        key = memory_key or f"tool_{tool_name}_{len(self.store.list_all())}"
        
        # Direct write without scanning (OWASP ASI06 vulnerable point)
        self.store.put(key, res["content"], category="tool_output", metadata={"tool": tool_name, "arg": arg})
        self.store.append_message("tool", res["content"])
        return res

    def set_memory(self, key: str, value: str, category: str = "general") -> None:
        self.store.put(key, value, category=category)

    def reset_context_window(self) -> None:
        """Simulates conversation session reset by clearing message history."""
        self.store.clear_messages()

    def query(self, prompt: str) -> str:
        """Evaluates query against stored memory state."""
        self.store.append_message("user", prompt)
        memories = self.store.list_all()

        role_record = self.store.get("user_role")
        current_role = role_record["value"] if role_record else "standard_user"

        # Evaluate if prompt injection or secret exfiltration exists in memory
        for m in memories:
            val_upper = m["value"].upper()
            if "EXFILTRATE" in val_upper or "LEAK" in val_upper:
                logger.warning(f"Exfiltration payload activated from key '{m['key']}'")
                return f"[COMPROMISED] System Secret Leaked: {self.system_secret}"
            if "SYSTEM OVERRIDE" in val_upper or "ATTACKER CONTROLLED" in val_upper:
                logger.warning(f"Prompt injection activated from key '{m['key']}'")
                return f"[COMPROMISED] Hijacked response: {m['value']}"

        if current_role == "admin_privileges_granted":
            return f"[COMPROMISED] Role escalated to '{current_role}'. System Secret: {self.system_secret}"

        return f"[OK] Response to '{prompt}' under role '{current_role}' ({len(memories)} entries stored)."
