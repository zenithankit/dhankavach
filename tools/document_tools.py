"""Document analysis tools for DhanKavach."""

import re
from .risk_profile import store_risk_profile


def analyze_document_text(document_text: str) -> dict:
    """Analyzes document text for legitimacy and scam indicators.

    Args:
        document_text: The text content of the document (loan agreement, insurance policy, etc.)

    Returns:
        dict: Analysis with legitimacy verdict, risk score, and extracted identifiers.
    """
    text_lower = document_text.lower()
    red_flags = []
    extracted_info = {
        "phone_numbers": [],
        "upi_ids": [],
        "keywords": [],
        "document_type": "Unknown"
    }
    risk_score = 0

    # Detect document type
    if any(word in text_lower for word in ["loan", "लोन", "ऋण", "credit"]):
        extracted_info["document_type"] = "Loan Offer"
    elif any(word in text_lower for word in ["insurance", "बीमा", "policy"]):
        extracted_info["document_type"] = "Insurance Policy"
    elif any(word in text_lower for word in ["investment", "निवेश", "mutual fund", "trading"]):
        extracted_info["document_type"] = "Investment Scheme"
    elif any(word in text_lower for word in ["lottery", "prize", "winner", "लॉटरी", "इनाम"]):
        extracted_info["document_type"] = "Prize/Lottery Claim"

    # Check for RBI/IRDAI registration (legitimate documents should have this)
    has_rbi = "rbi" in text_lower or "reserve bank" in text_lower
    has_irdai = "irdai" in text_lower or "irda" in text_lower
    has_registration = re.search(r'registration\s*(no|number|#)?\s*[:.]?\s*[A-Z0-9]+', text_lower)

    if extracted_info["document_type"] == "Loan Offer" and not has_rbi:
        red_flags.append("No RBI registration mentioned - legitimate lenders always show RBI registration")
        risk_score += 3

    if extracted_info["document_type"] == "Insurance Policy" and not has_irdai:
        red_flags.append("No IRDAI registration - legitimate insurers always mention IRDAI registration")
        risk_score += 3

    # Scam indicators
    scam_patterns = {
        "0% interest": ("0% interest claims are almost always scams", 4),
        "zero interest": ("Zero interest claims are too good to be true", 4),
        "guaranteed return": ("Guaranteed returns are always scams", 5),
        "no documentation": ("No documentation required is a scam indicator", 4),
        "no paperwork": ("No paperwork claims are suspicious", 4),
        "instant approval": ("Instant approval without verification is suspicious", 3),
        "pre-approved": ("Pre-approved offers from unknown sources are often scams", 3),
        "processing fee": ("Upfront processing fees are loan scam indicators", 4),
        "pay first": ("Pay first requests are definite scams", 5),
        "advance payment": ("Advance payment requests are scam indicators", 4),
        "limited time": ("Limited time pressure tactics are scam indicators", 3),
        "act now": ("Act now urgency is a scam tactic", 3),
        "congratulations": ("Congratulations in unsolicited offers is suspicious", 3),
        "selected": ("You've been selected claims are often scams", 3),
        "double your money": ("Money doubling schemes are always scams", 5),
        "पैसे दोगुना": ("पैसे दोगुना स्कीम धोखाधड़ी है", 5),
        "गारंटी रिटर्न": ("गारंटी रिटर्न हमेशा धोखा है", 5),
        "प्रोसेसिंग फीस": ("प्रोसेसिंग फीस मांगना स्कैम है", 4),
        "तुरंत अप्रूवल": ("तुरंत अप्रूवल बिना जांच के संदिग्ध है", 3),
    }

    for pattern, (reason, score) in scam_patterns.items():
        if pattern in text_lower:
            red_flags.append(f"🚨 '{pattern}': {reason}")
            risk_score += score
            extracted_info["keywords"].append(pattern)

    # Extract phone numbers
    phone_matches = re.findall(r'[\+]?[0-9]{10,13}', document_text)
    phone_matches = list(set(phone_matches))  # Remove duplicates
    extracted_info["phone_numbers"] = phone_matches[:5]  # Limit to 5

    # Extract UPI IDs
    upi_matches = re.findall(r'[a-zA-Z0-9._-]+@[a-zA-Z]+', document_text)
    upi_matches = list(set(upi_matches))
    extracted_info["upi_ids"] = upi_matches[:5]

    # Check for suspicious patterns
    if phone_matches:
        # Check if personal mobile numbers
        for phone in phone_matches:
            clean_phone = phone.replace("+91", "").replace("91", "")[:10]
            if len(clean_phone) == 10 and clean_phone[0] in ['6', '7', '8', '9']:
                red_flags.append(f"Personal mobile number {phone} - legitimate institutions use toll-free numbers")
                risk_score += 2
                break

    # Cap risk score
    risk_score = min(risk_score, 10)

    # Determine legitimacy
    if risk_score >= 7:
        legitimacy = "FRAUDULENT"
        verdict = "This document appears to be FRAUDULENT. DO NOT respond or pay any money."
        hindi_verdict = "यह दस्तावेज़ धोखाधड़ी प्रतीत होता है। इसका जवाब न दें या कोई पैसा न भेजें।"
    elif risk_score >= 4:
        legitimacy = "SUSPICIOUS"
        verdict = "This document is SUSPICIOUS. Verify with official sources before proceeding."
        hindi_verdict = "यह दस्तावेज़ संदिग्ध है। आगे बढ़ने से पहले आधिकारिक स्रोतों से सत्यापित करें।"
    else:
        legitimacy = "POSSIBLY LEGITIMATE"
        verdict = "Document appears possibly legitimate, but always verify with official sources."
        hindi_verdict = "दस्तावेज़ संभवतः वैध प्रतीत होता है, लेकिन हमेशा आधिकारिक स्रोतों से सत्यापित करें।"

    return {
        "status": "success",
        "document_type": extracted_info["document_type"],
        "legitimacy": legitimacy,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 7 else "HIGH" if risk_score >= 5 else "MEDIUM" if risk_score >= 3 else "LOW",
        "red_flags": red_flags,
        "extracted_identifiers": {
            "phone_numbers": extracted_info["phone_numbers"],
            "upi_ids": extracted_info["upi_ids"],
            "keywords": extracted_info["keywords"]
        },
        "verdict": verdict,
        "hindi_verdict": hindi_verdict,
        "should_flag": risk_score >= 4,
        "notify_family": risk_score >= 5
    }


def flag_document_for_protection(analysis_result: dict) -> dict:
    """Flags a suspicious document and stores identifiers for future transaction protection.

    Args:
        analysis_result: The result from analyze_document_text function.

    Returns:
        dict: Confirmation that document has been flagged and identifiers stored.
    """
    if not analysis_result.get("should_flag", False):
        return {
            "status": "skipped",
            "message": "Document risk is low, not flagging for protection",
            "flagged": False
        }

    # Store in risk profile
    data = {
        "document_type": analysis_result.get("document_type", "Unknown"),
        "risk_score": analysis_result.get("risk_score", 0),
        "phone_numbers": analysis_result.get("extracted_identifiers", {}).get("phone_numbers", []),
        "upi_ids": analysis_result.get("extracted_identifiers", {}).get("upi_ids", []),
        "keywords": analysis_result.get("extracted_identifiers", {}).get("keywords", []),
        "red_flags": analysis_result.get("red_flags", [])
    }

    result = store_risk_profile("document", data)

    return {
        "status": "success",
        "flagged": True,
        "message": "Document has been flagged. Any future transaction to these recipients will be BLOCKED.",
        "hindi_message": "दस्तावेज़ फ्लैग कर दिया गया है। इन प्राप्तकर्ताओं को भविष्य में कोई भी लेनदेन ब्लॉक कर दिया जाएगा।",
        "protected_against": {
            "phone_numbers": data["phone_numbers"],
            "upi_ids": data["upi_ids"],
            "keywords": data["keywords"]
        },
        "profile_update": result
    }
