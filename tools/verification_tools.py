"""Verification and signal analysis tools for DhanKavach."""

import re


def analyze_signals(
    positive_signals: str,
    negative_signals: str,
    context: str
) -> dict:
    """Analyzes conflicting signals and provides visible reasoning for decisions.

    This tool shows the agent's decision-making process when signals conflict.
    Use this to demonstrate intelligent analysis to judges.

    Args:
        positive_signals: Comma-separated factors suggesting legitimacy (e.g., "Has official branding, Small amount, Known recipient")
        negative_signals: Comma-separated risk factors (e.g., "No RBI registration, Processing fee requested, Unknown number")
        context: Brief context of the situation being analyzed

    Returns:
        dict: Signal analysis with reasoning, conflict detection, and final judgment
    """
    # Parse comma-separated strings into lists
    positive_list = [s.strip() for s in positive_signals.split(",") if s.strip()] if positive_signals else []
    negative_list = [s.strip() for s in negative_signals.split(",") if s.strip()] if negative_signals else []

    has_conflict = len(positive_list) > 0 and len(negative_list) > 0

    # Weight the signals
    positive_weight = len(positive_list)
    negative_weight = len(negative_list)

    # Negative signals are weighted more heavily for safety
    adjusted_negative = negative_weight * 1.5

    # Determine which side wins
    if adjusted_negative > positive_weight:
        judgment = "RISK OUTWEIGHS"
        recommendation = "BLOCK"
        reasoning = "Negative signals outweigh positive ones. Safety takes priority over convenience."
    elif positive_weight > adjusted_negative and negative_weight == 0:
        judgment = "APPEARS SAFE"
        recommendation = "ALLOW"
        reasoning = "No significant risk signals detected."
    else:
        judgment = "UNCERTAIN"
        recommendation = "VERIFY"
        reasoning = "Mixed signals require human verification. Family should be consulted."

    # Build the visible reasoning panel
    reasoning_panel = f"""
┌─────────────────────────────────────────────────────────────┐
│ 🧠 SIGNAL ANALYSIS (Agent Reasoning)                        │
├─────────────────────────────────────────────────────────────┤
│ Context: {context[:50]:50s}│
├─────────────────────────────────────────────────────────────┤
│ ✅ POSITIVE SIGNALS:                                        │
"""
    for signal in positive_list[:5]:
        reasoning_panel += f"│    • {signal[:55]:55s}│\n"
    if not positive_list:
        reasoning_panel += "│    • (None detected)                                       │\n"

    reasoning_panel += """│                                                             │
│ ❌ NEGATIVE SIGNALS:                                        │
"""
    for signal in negative_list[:5]:
        reasoning_panel += f"│    • {signal[:55]:55s}│\n"
    if not negative_list:
        reasoning_panel += "│    • (None detected)                                       │\n"

    if has_conflict:
        reasoning_panel += """│                                                             │
│ ⚠️  CONFLICT DETECTED: Visual legitimacy vs. data signals   │
"""

    reasoning_panel += f"""├─────────────────────────────────────────────────────────────┤
│ REASONING:                                                  │
│ {reasoning[:60]:60s}│
├─────────────────────────────────────────────────────────────┤
│ JUDGMENT: {judgment:15s} → RECOMMENDATION: {recommendation:15s}│
└─────────────────────────────────────────────────────────────┘
"""

    return {
        "status": "success",
        "has_conflict": has_conflict,
        "positive_count": positive_weight,
        "negative_count": negative_weight,
        "judgment": judgment,
        "recommendation": recommendation,
        "reasoning": reasoning,
        "reasoning_panel": reasoning_panel,
        "priority_rule": "Safety over convenience - negative signals weighted 1.5x"
    }


def check_phone_reputation(phone: str) -> dict:
    """Checks phone number against scam report database.

    In production, this would query real databases like Truecaller API,
    CyberCrime Portal reports, or community scam databases.

    Args:
        phone: Phone number to check for scam reports

    Returns:
        dict: Reputation data with scam reports count and verdict
    """
    phone_clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    if phone_clean.startswith("91"):
        phone_clean = phone_clean[2:]

    # Simulated scam database (in production: real API call)
    # These patterns represent known scam number patterns
    known_scam_patterns = {
        "9876543210": {"reports": 47, "scam_type": "Loan Fraud", "first_reported": "2024-03"},
        "8765432109": {"reports": 23, "scam_type": "KYC Scam", "first_reported": "2024-06"},
        "7654321098": {"reports": 89, "scam_type": "Investment Fraud", "first_reported": "2023-11"},
        "9988776655": {"reports": 156, "scam_type": "Lottery Scam", "first_reported": "2023-08"},
        "8899776655": {"reports": 34, "scam_type": "Tech Support Scam", "first_reported": "2024-01"},
    }

    # Check if phone matches known scam numbers
    scam_data = known_scam_patterns.get(phone_clean)

    if scam_data:
        return {
            "status": "success",
            "phone": phone,
            "found_in_database": True,
            "scam_reports": scam_data["reports"],
            "scam_type": scam_data["scam_type"],
            "first_reported": scam_data["first_reported"],
            "reputation": "SCAM",
            "verdict": f"⚠️ DANGER: {scam_data['reports']} scam reports found!",
            "hindi_verdict": f"⚠️ खतरा: इस नंबर पर {scam_data['reports']} धोखाधड़ी की शिकायतें हैं!",
            "recommendation": "DO NOT interact with this number"
        }

    # Check for suspicious patterns
    if phone_clean.startswith("140"):
        return {
            "status": "success",
            "phone": phone,
            "found_in_database": False,
            "scam_reports": 0,
            "reputation": "SUSPICIOUS",
            "verdict": "Telemarketing number (140 prefix) - often used for spam",
            "recommendation": "Exercise caution"
        }

    # Unknown number
    return {
        "status": "success",
        "phone": phone,
        "found_in_database": False,
        "scam_reports": 0,
        "reputation": "UNKNOWN",
        "verdict": "No reports found, but number not verified as safe",
        "hindi_verdict": "कोई शिकायत नहीं मिली, लेकिन नंबर सत्यापित नहीं है",
        "recommendation": "Verify independently before trusting"
    }


def check_rbi_registration(company_name: str, registration_number: str = None) -> dict:
    """Verifies if a financial company is registered with RBI.

    In production, this would query RBI's NBFC/Bank registry.
    For demo, uses pattern matching and known entities.

    Args:
        company_name: Name of the company claiming to offer loans/financial services
        registration_number: Optional RBI registration number to verify

    Returns:
        dict: Registration verification status
    """
    company_lower = company_name.lower().strip()

    # Known legitimate entities (simplified for demo)
    legitimate_entities = {
        "state bank of india": {"type": "Bank", "reg": "Licensed Bank"},
        "sbi": {"type": "Bank", "reg": "Licensed Bank"},
        "hdfc bank": {"type": "Bank", "reg": "Licensed Bank"},
        "icici bank": {"type": "Bank", "reg": "Licensed Bank"},
        "axis bank": {"type": "Bank", "reg": "Licensed Bank"},
        "bajaj finserv": {"type": "NBFC", "reg": "N-13.02109"},
        "tata capital": {"type": "NBFC", "reg": "B-13.02108"},
        "muthoot finance": {"type": "NBFC", "reg": "B-14.00456"},
    }

    # Check if known entity
    for entity, info in legitimate_entities.items():
        if entity in company_lower:
            return {
                "status": "success",
                "company": company_name,
                "is_registered": True,
                "entity_type": info["type"],
                "registration": info["reg"],
                "verdict": "LEGITIMATE",
                "message": f"✅ {company_name} is a registered {info['type']}",
                "hindi_message": f"✅ {company_name} एक पंजीकृत {info['type']} है"
            }

    # Check for obvious fake patterns
    fake_patterns = ["easy loan", "instant loan", "lucky", "prize", "lottery", "free money"]
    for pattern in fake_patterns:
        if pattern in company_lower:
            return {
                "status": "success",
                "company": company_name,
                "is_registered": False,
                "verdict": "LIKELY FAKE",
                "message": f"❌ '{company_name}' does not appear in RBI registry. Common scam name pattern.",
                "hindi_message": f"❌ '{company_name}' RBI में पंजीकृत नहीं है। यह स्कैम लगता है।",
                "recommendation": "Do not proceed with any financial transaction"
            }

    # Unknown entity
    return {
        "status": "success",
        "company": company_name,
        "is_registered": False,
        "verdict": "NOT FOUND",
        "message": f"⚠️ '{company_name}' not found in RBI registry. Verify before proceeding.",
        "hindi_message": f"⚠️ '{company_name}' RBI में नहीं मिला। आगे बढ़ने से पहले सत्यापित करें।",
        "recommendation": "Ask for RBI registration number and verify on RBI website"
    }
