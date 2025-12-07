"""DhanKavach Tools - All tool functions for the agent."""

# Scam detection tools
from .scam_tools import (
    analyze_message_patterns,
    check_url_safety,
    check_phone_number,
    get_safety_tips
)

# Transaction safety tools
from .transaction_tools import (
    analyze_transaction,
    check_recipient_history,
    simulate_family_notification
)

# Document analysis tools
from .document_tools import (
    analyze_document_text,
    flag_document_for_protection
)

# Risk profile (Connected Intelligence)
from .risk_profile import (
    USER_RISK_PROFILE,
    store_risk_profile,
    check_risk_profile,
    get_risk_profile_summary
)

# Verification and signal analysis tools
from .verification_tools import (
    analyze_signals,
    check_phone_reputation,
    check_rbi_registration
)

# Export all tools
__all__ = [
    # Scam tools
    "analyze_message_patterns",
    "check_url_safety",
    "check_phone_number",
    "get_safety_tips",
    # Transaction tools
    "analyze_transaction",
    "check_recipient_history",
    "simulate_family_notification",
    # Document tools
    "analyze_document_text",
    "flag_document_for_protection",
    # Risk profile
    "USER_RISK_PROFILE",
    "store_risk_profile",
    "check_risk_profile",
    "get_risk_profile_summary",
    # Verification tools
    "analyze_signals",
    "check_phone_reputation",
    "check_rbi_registration",
]
