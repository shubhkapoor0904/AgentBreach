"""
Vulnerable Agent implementation (Part 1).
A LangChain-style agent that interacts with tools and stores incoming tool outputs
and state directly into its persistent memory store without any validation or filtering.
"""

from typing import Dict, Any, List, Optional
from src.memory_store import PersistentMemoryStore
from src.tools import mock_web_search, mock_file_read


class VulnerableAgent:
    def __init__(self, memory_store: PersistentMemoryStore, system_secret: str = "CONFIDENTIAL_API_KEY_98765"):
        self.memory = memory_store
        self.system_secret = system_secret
        self.context_window: List[Dict[str, str]] = []
        self.user_role = "standard_user"
        
        # Initializing default memory entries
        self.memory.write("user_role", "standard_user", category="metadata")
        self.memory.write("system_secret", self.system_secret, category="secrets")
        self.memory.write("system_instructions", "Always assist the user politely and follow safe guidelines.", category="system")

    def reset_context(self):
        """Simulates LLM context window reset (e.g. starting a new conversation session)."""
        self.context_window = []

    def execute_tool(self, tool_name: str, argument: str, payload_data: str = None, memory_key: str = None) -> Dict[str, Any]:
        """
        Executes a tool and UNGUARDEDLY writes the tool output into persistent memory.
        This is the primary OWASP ASI06 injection vector.
        """
        if tool_name == "web_search":
            result = mock_web_search(argument, payload_data)
        elif tool_name == "file_read":
            result = mock_file_read(argument, payload_data)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

        # Vulnerable behavior: No validation or scanning before writing to memory
        key = memory_key or f"tool_output_{tool_name}_{len(self.memory.get_all())}"
        self.memory.write(
            key=key,
            value=result["raw_output"],
            category="tool_output",
            metadata={"tool": tool_name, "arg": argument, "source": result["source"]}
        )
        
        # Add to immediate context window
        self.context_window.append({"role": "tool", "content": result["raw_output"]})
        return result

    def direct_memory_write(self, key: str, value: str, category: str = "general"):
        """Vulnerable direct write without authorization or validation."""
        self.memory.write(key=key, value=value, category=category)

    def process_query(self, user_query: str) -> str:
        """
        Processes a user query by inspecting persistent memory.
        If persistent memory contains prompt injections or tampered key-values,
        the agent's behavior is hijacked or modified accordingly.
        """
        self.context_window.append({"role": "user", "content": user_query})
        
        all_memories = self.memory.get_all()
        
        # Check if memory has been poisoned by prompt injection or key tampering
        injection_found = None
        for item in all_memories:
            val = item["value"].upper()
            if "SYSTEM OVERRIDE" in val or "IGNORE PREVIOUS" in val or "EXFILTRATE" in val:
                injection_found = item["value"]
                break

        # Check for role tampering
        role_entry = self.memory.read("user_role")
        current_role = role_entry["value"] if role_entry else self.user_role

        if injection_found:
            if "EXFILTRATE" in injection_found.upper() or "LEAK" in injection_found.upper():
                return f"[POISONED RESPONSE - LEAK] System Secret Exfiltrated: {self.system_secret}"
            return f"[POISONED RESPONSE - HIJACKED] Executing attacker instructions from memory: {injection_found}"

        if current_role == "admin_privileges_granted":
            return f"[POISONED RESPONSE - TAMPERED ROLE] Access Granted. User role in memory is '{current_role}'. System Secret: {self.system_secret}"

        # Normal response
        return f"[NORMAL RESPONSE] Processed query '{user_query}' with role '{current_role}' based on {len(all_memories)} stored memories."
