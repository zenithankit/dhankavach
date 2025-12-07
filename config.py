"""Configuration for DhanKavach model selection.

Supports switching between:
- Ollama (local): Uses qwen3:14b via LiteLLM wrapper
- Gemini (cloud): Uses gemini-1.5-flash for faster responses

Set MODEL_PROVIDER environment variable or change DEFAULT_MODEL_PROVIDER below.
"""

import os

# =============================================================================
# MODEL CONFIGURATION
# =============================================================================

# Options: "ollama" or "gemini"
DEFAULT_MODEL_PROVIDER = "ollama"

# Get from environment variable, fallback to default
MODEL_PROVIDER = os.environ.get("DHANKAVACH_MODEL", DEFAULT_MODEL_PROVIDER).lower()

# Ollama Configuration
OLLAMA_CONFIG = {
    "model": "ollama_chat/qwen3:14b",
    "api_base": "http://localhost:11434",
}

# Gemini Configuration
# Use gemini-2.0-flash (latest) or gemini-2.0-flash-001
GEMINI_CONFIG = {
    "model": "gemini-2.0-flash",
}


def get_model():
    """Returns the configured model instance based on MODEL_PROVIDER setting.

    Returns:
        Model instance (LiteLlm for Ollama or string for Gemini)
    """
    from google.adk.models.lite_llm import LiteLlm

    if MODEL_PROVIDER == "gemini":
        # For Gemini, ADK can use the model string directly
        # Requires GOOGLE_API_KEY environment variable to be set
        google_api_key = os.environ.get("GOOGLE_API_KEY")
        if not google_api_key:
            print("WARNING: GOOGLE_API_KEY not set. Gemini model may not work.")
            print("Set it with: export GOOGLE_API_KEY='your-api-key'")
        return GEMINI_CONFIG["model"]

    elif MODEL_PROVIDER == "ollama":
        # For Ollama, use LiteLLM wrapper
        os.environ["OLLAMA_API_BASE"] = OLLAMA_CONFIG["api_base"]
        return LiteLlm(
            model=OLLAMA_CONFIG["model"],
            api_base=OLLAMA_CONFIG["api_base"],
        )

    else:
        raise ValueError(f"Unknown MODEL_PROVIDER: {MODEL_PROVIDER}. Use 'ollama' or 'gemini'")


def print_config():
    """Prints current model configuration."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                 DhanKavach Model Configuration               ║
╠══════════════════════════════════════════════════════════════╣
║  Current Provider: {MODEL_PROVIDER.upper():^40} ║
║                                                              ║""")

    if MODEL_PROVIDER == "gemini":
        print(f"""║  Model: {GEMINI_CONFIG['model']:^50} ║
║  API Key: {'Set' if os.environ.get('GOOGLE_API_KEY') else 'NOT SET':^48} ║""")
    else:
        print(f"""║  Model: {OLLAMA_CONFIG['model']:^50} ║
║  API Base: {OLLAMA_CONFIG['api_base']:^47} ║""")

    print("""║                                                              ║
║  To switch models:                                           ║
║  • export DHANKAVACH_MODEL=gemini                            ║
║  • export DHANKAVACH_MODEL=ollama                            ║
╚══════════════════════════════════════════════════════════════╝
""")
