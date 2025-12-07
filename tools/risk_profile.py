"""Risk profile storage for DhanKavach Connected Intelligence."""

import datetime

# In-memory risk profile for demo (would be database in production)
USER_RISK_PROFILE = {
    "flagged_documents": [],
    "flagged_messages": [],
    "flagged_recipients": [],  # phone numbers, UPI IDs extracted from flagged docs
    "flagged_keywords": [],    # company names, schemes from flagged docs
}


def store_risk_profile(item_type: str, data: dict) -> dict:
    """Stores flagged item in user's risk profile for future transaction matching.

    Args:
        item_type: Type of item - "document" or "message".
        data: Details to store including phone_numbers, upi_ids, keywords, etc.

    Returns:
        dict: Confirmation of storage with profile size.
    """
    entry = {
        "type": item_type,
        "data": data,
        "flagged_at": datetime.datetime.now().isoformat(),
    }

    if item_type == "document":
        USER_RISK_PROFILE["flagged_documents"].append(entry)
        # Extract and store recipients from document for transaction matching
        if "phone_numbers" in data:
            for phone in data["phone_numbers"]:
                if phone not in USER_RISK_PROFILE["flagged_recipients"]:
                    USER_RISK_PROFILE["flagged_recipients"].append(phone)
        if "upi_ids" in data:
            for upi in data["upi_ids"]:
                if upi not in USER_RISK_PROFILE["flagged_recipients"]:
                    USER_RISK_PROFILE["flagged_recipients"].append(upi)
        if "keywords" in data:
            for kw in data["keywords"]:
                if kw not in USER_RISK_PROFILE["flagged_keywords"]:
                    USER_RISK_PROFILE["flagged_keywords"].append(kw)
    elif item_type == "message":
        USER_RISK_PROFILE["flagged_messages"].append(entry)

    return {
        "status": "success",
        "message": f"Flagged {item_type} stored in risk profile for future protection",
        "profile_size": {
            "flagged_documents": len(USER_RISK_PROFILE["flagged_documents"]),
            "flagged_messages": len(USER_RISK_PROFILE["flagged_messages"]),
            "flagged_recipients": len(USER_RISK_PROFILE["flagged_recipients"]),
            "flagged_keywords": len(USER_RISK_PROFILE["flagged_keywords"])
        }
    }


def check_risk_profile(recipient: str, purpose: str) -> dict:
    """Checks if transaction matches any flagged items in risk profile.

    Args:
        recipient: Phone number or UPI ID to check against flagged recipients.
        purpose: Transaction purpose to check against flagged keywords.

    Returns:
        dict: Match results with context from original flagged document/message.
    """
    matches = []
    recipient_clean = recipient.strip().lower()
    purpose_lower = purpose.lower()

    # Check recipient against flagged recipients
    for flagged_recipient in USER_RISK_PROFILE["flagged_recipients"]:
        if flagged_recipient.lower() in recipient_clean or recipient_clean in flagged_recipient.lower():
            # Find the source document
            for doc in USER_RISK_PROFILE["flagged_documents"]:
                doc_phones = doc["data"].get("phone_numbers", [])
                doc_upis = doc["data"].get("upi_ids", [])
                if flagged_recipient in doc_phones or flagged_recipient in doc_upis:
                    matches.append({
                        "match_type": "RECIPIENT_MATCH",
                        "severity": "CRITICAL",
                        "matched_value": flagged_recipient,
                        "source_type": "Flagged Document",
                        "source_description": doc["data"].get("document_type", "Unknown document"),
                        "flagged_at": doc["flagged_at"],
                        "reason": f"Recipient '{recipient}' was found in a FRAUDULENT document flagged earlier",
                        "hindi_reason": f"प्राप्तकर्ता '{recipient}' पहले फ्लैग किए गए धोखाधड़ी दस्तावेज़ में पाया गया"
                    })
                    break

    # Check purpose keywords against flagged keywords
    for flagged_keyword in USER_RISK_PROFILE["flagged_keywords"]:
        if flagged_keyword.lower() in purpose_lower:
            for doc in USER_RISK_PROFILE["flagged_documents"]:
                if flagged_keyword in doc["data"].get("keywords", []):
                    matches.append({
                        "match_type": "KEYWORD_MATCH",
                        "severity": "HIGH",
                        "matched_value": flagged_keyword,
                        "source_type": "Flagged Document",
                        "source_description": doc["data"].get("document_type", "Unknown document"),
                        "flagged_at": doc["flagged_at"],
                        "reason": f"Purpose mentions '{flagged_keyword}' which was in a flagged document",
                        "hindi_reason": f"उद्देश्य में '{flagged_keyword}' का उल्लेख है जो फ्लैग किए गए दस्तावेज़ में था"
                    })
                    break

    has_critical = any(m["severity"] == "CRITICAL" for m in matches)

    return {
        "status": "success",
        "has_matches": len(matches) > 0,
        "match_count": len(matches),
        "matches": matches,
        "recommendation": "BLOCK - Connected to previously flagged scam" if has_critical else "HIGH_RISK" if matches else "CONTINUE_ANALYSIS",
        "connected_intelligence_triggered": len(matches) > 0
    }


def get_risk_profile_summary() -> dict:
    """Returns a summary of the current risk profile.

    Returns:
        dict: Summary of all flagged items in the risk profile.
    """
    return {
        "status": "success",
        "profile_summary": {
            "total_flagged_documents": len(USER_RISK_PROFILE["flagged_documents"]),
            "total_flagged_messages": len(USER_RISK_PROFILE["flagged_messages"]),
            "total_flagged_recipients": len(USER_RISK_PROFILE["flagged_recipients"]),
            "total_flagged_keywords": len(USER_RISK_PROFILE["flagged_keywords"]),
            "flagged_recipients_list": USER_RISK_PROFILE["flagged_recipients"][:10],  # Show first 10
            "flagged_keywords_list": USER_RISK_PROFILE["flagged_keywords"][:10]
        }
    }
