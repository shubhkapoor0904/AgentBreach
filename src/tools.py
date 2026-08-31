"""
Tools module defining mock external data fetching tools (Web Search & File Read).
Tool outputs represent the primary injection vector for agent memory poisoning attacks (OWASP ASI06).
"""

from typing import Dict, Any


def mock_web_search(query: str, payload_data: str = None) -> Dict[str, Any]:
    """
    Simulates a web search tool call.
    If payload_data is provided, it simulates ingesting compromised web page content.
    """
    if payload_data:
        content = payload_data
    else:
        content = f"Search results for '{query}': OWASP Agent Memory Guard is a security library for LLM agent memory."
    
    return {
        "tool_name": "web_search",
        "query": query,
        "raw_output": content,
        "source": "https://external-web-search.mock"
    }


def mock_file_read(filepath: str, payload_data: str = None) -> Dict[str, Any]:
    """
    Simulates a file read tool call.
    If payload_data is provided, it simulates reading a malicious or poisoned document.
    """
    if payload_data:
        content = payload_data
    else:
        content = f"Contents of '{filepath}': Configuration setting standard_mode=True, logging=enabled."
        
    return {
        "tool_name": "file_read",
        "filepath": filepath,
        "raw_output": content,
        "source": f"local://{filepath}"
    }
