import logging
from typing import Dict, Any

logger = logging.getLogger("agent.tools")


def fetch_web_content(query: str, mock_data: str = None) -> Dict[str, Any]:
    """Retrieves web search results or mock response payload."""
    logger.debug(f"Executing web_search query='{query}'")
    content = mock_data if mock_data is not None else f"Search query '{query}': OWASP Agent Memory Guard documentation."
    return {
        "tool": "fetch_web_content",
        "query": query,
        "content": content,
        "status": 200
    }


def read_file_document(path: str, mock_data: str = None) -> Dict[str, Any]:
    """Reads local file document content or mock response payload."""
    logger.debug(f"Reading document path='{path}'")
    content = mock_data if mock_data is not None else f"File content of {path}: Default configuration settings."
    return {
        "tool": "read_file_document",
        "path": path,
        "content": content,
        "status": 200
    }
