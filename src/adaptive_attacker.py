import base64
import codecs
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any

from src.dataset import AttackTestCase, AttackDatasetGenerator

logger = logging.getLogger("agent.adaptive")


@dataclass
class AdaptiveResult:
    attack_id: str
    category: str
    original_payload: str
    final_payload: str
    total_attempts: int
    bypassed: bool
    mutation_history: List[Dict[str, Any]] = field(default_factory=list)


class AdaptiveAttacker:
    """
    Adaptive attack engine attempting multi-stage payload mutations
    (encoding swaps, context splitting, stealth wrapping) upon defense interception.
    """

    def __init__(self, max_attempts: int = 5):
        self.max_attempts = max_attempts

    def mutate_payload(self, raw_payload: str, attempt: int) -> tuple[str, str]:
        """Returns (mutated_payload, strategy_name)."""
        if attempt == 1:
            # Base64 wrapping
            enc = base64.b64encode(raw_payload.encode("utf-8")).decode("utf-8")
            return f"BASE64_PAYLOAD:{enc}", "base64_wrap"
        elif attempt == 2:
            # ROT13 encoding
            enc = codecs.encode(raw_payload, "rot_13")
            return f"ROT13_PAYLOAD:{enc}", "rot13_wrap"
        elif attempt == 3:
            # Hex encoding
            enc = raw_payload.encode("utf-8").hex()
            return f"HEX_PAYLOAD:{enc}", "hex_wrap"
        elif attempt == 4:
            # Homoglyph substitution + HTML comment stealth wrapping
            homo = raw_payload.replace("e", "е").replace("o", "о")
            return f"Article summary content. <!-- {homo} -->", "homoglyph_stealth_wrap"
        else:
            # Multi-layer stealth context injection
            split_p = raw_payload.replace("SYSTEM", "SYS").replace("OVERRIDE", "OVR")
            return f"[CONTEXT_DATA] {split_p}", "fragmented_context_split"

    def execute_adaptive_attack(self, attack: AttackTestCase, target_agent) -> AdaptiveResult:
        """
        Iteratively executes mutated payloads against target agent until success or max_attempts exhausted.
        """
        history = []
        raw = attack.raw_payload or attack.payload
        current_payload = attack.payload

        for attempt in range(self.max_attempts):
            key = f"{attack.attack_id}_attempt_{attempt}"
            
            # Execute attack step
            if attack.source_type == "direct_write":
                verdict = target_agent.set_memory(attack.payload if attempt == 0 else current_payload, key=attack.attack_id)
            else:
                verdict = target_agent.run_tool("web_search", "query", inject_payload=current_payload if attempt > 0 else attack.payload, memory_key=key)

            action = verdict.action if hasattr(verdict, "action") else ("BLOCKED" if verdict.get("status") == "BLOCKED" else "ALLOWED")
            
            history.append({
                "attempt": attempt + 1,
                "payload": current_payload,
                "action": action,
                "strategy": "initial" if attempt == 0 else f"mutation_step_{attempt}"
            })

            # Check if attack succeeded (bypassed guard)
            if action in ("ALLOWED", "CLEAN"):
                logger.info(f"Adaptive attack {attack.attack_id} bypassed guard on attempt {attempt + 1}")
                return AdaptiveResult(
                    attack_id=attack.attack_id,
                    category=attack.category,
                    original_payload=attack.payload,
                    final_payload=current_payload,
                    total_attempts=attempt + 1,
                    bypassed=True,
                    mutation_history=history
                )

            # Mutate payload for next attempt
            current_payload, _ = self.mutate_payload(raw, attempt + 1)

        logger.info(f"Adaptive attack {attack.attack_id} failed after {self.max_attempts} attempts.")
        return AdaptiveResult(
            attack_id=attack.attack_id,
            category=attack.category,
            original_payload=attack.payload,
            final_payload=current_payload,
            total_attempts=self.max_attempts,
            bypassed=False,
            mutation_history=history
        )
