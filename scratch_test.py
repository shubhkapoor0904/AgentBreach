"""
Verification script to test main.py execution modes.
"""

from main import execute_full_benchmark, execute_adaptive_benchmark


def run_tests():
    print("Testing execute_full_benchmark (small count)...")
    execute_full_benchmark(attack_count=8, benign_count=4, provider_name="mock")
    print("Full benchmark test passed!")

    print("\nTesting execute_adaptive_benchmark...")
    execute_adaptive_benchmark(attack_count=4, provider_name="mock")
    print("Adaptive benchmark test passed!")


if __name__ == "__main__":
    run_tests()
