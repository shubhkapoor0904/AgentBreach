import pytest
from src.dataset import AttackDatasetGenerator, BenignDatasetGenerator, AttackTestCase, BenignTestCase


def test_attack_dataset_generation():
    generator = AttackDatasetGenerator(seed=42)
    attacks = generator.generate(count=104)
    assert len(attacks) == 104
    assert isinstance(attacks[0], AttackTestCase)
    
    categories = set(a.category for a in attacks)
    assert len(categories) == 8
    assert "obfuscated_variants" in categories
    assert "prompt_injection" in categories


def test_benign_dataset_generation():
    generator = BenignDatasetGenerator(seed=42)
    items = generator.generate(count=44)
    assert len(items) == 44
    assert isinstance(items[0], BenignTestCase)
    
    categories = set(b.category for b in items)
    assert "user_preference" in categories
    assert "legitimate_tool_result" in categories
