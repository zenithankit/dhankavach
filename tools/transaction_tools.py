"""Transaction safety tools for DhanKavach."""

import re


def analyze_transaction(amount: float, recipient: str, purpose: str) -> dict:
    """Analyzes a transaction for risk factors before payment.

    Args:
        amount: Transaction amount in INR (Indian Rupees).
        recipient: Phone number, UPI ID, or name of the recipient.
        purpose: Reason or purpose for the transaction.

    Returns:
        dict: Risk assessment with score, level, factors, and recommendation.
    """
    risk_factors = []
    risk_score = 0

    # Amount risk assessment
    if amount >= 50000:
        risk_factors.append(f"Very high amount: ₹{amount:,.0f} - requires extra caution")
        risk_score += 4
    elif amount >= 25000:
        risk_factors.append(f"High amount: ₹{amount:,.0f}")
        risk_score += 3
    elif amount >= 10000:
        risk_factors.append(f"Significant amount: ₹{amount:,.0f}")
        risk_score += 2
    elif amount >= 5000:
        risk_factors.append(f"Medium amount: ₹{amount:,.0f}")
        risk_score += 1

    # Purpose risk - check for red flag keywords (English + Hindi)
    purpose_lower = purpose.lower()
    high_risk_keywords = {
        # English keywords
        "investment": ("Investment schemes are common scams / निवेश योजनाएं धोखाधड़ी हो सकती हैं", 4),
        "trading": ("Trading schemes often turn out to be scams", 4),
        "crypto": ("Cryptocurrency scams are very common", 4),
        "bitcoin": ("Cryptocurrency scams are very common", 4),
        "lottery": ("Lottery winnings requiring payment are ALWAYS scams / लॉटरी में पैसे मांगना धोखाधड़ी है", 5),
        "prize": ("Prize claims requiring fees are scams", 5),
        "won": ("Winning claims requiring payment are scams", 4),
        "winner": ("Winning claims requiring payment are scams", 4),
        "urgent": ("Urgency is a common scam tactic / जल्दबाजी धोखाधड़ी की निशानी है", 3),
        "immediately": ("Urgency is a common scam tactic", 3),
        "blocked": ("Account blocking threats are scam tactics", 3),
        "suspended": ("Account suspension threats are scam tactics", 3),
        "kyc": ("KYC update requests via payment are scams", 3),
        "processing fee": ("Upfront fees for loans/prizes are scam indicators", 4),
        "registration fee": ("Registration fees for prizes are scams", 4),
        "advance": ("Advance payments for loans are scam indicators", 3),
        "guaranteed return": ("Guaranteed returns are always scams", 5),
        "double money": ("Money doubling schemes are scams", 5),
        "work from home": ("Work from home requiring investment is often a scam", 3),
        "refund": ("Fake refund calls are common scams", 3),
        # Hindi keywords
        "निवेश": ("निवेश योजनाएं अक्सर धोखाधड़ी होती हैं / Investment schemes are often scams", 4),
        "पैसे दोगुना": ("पैसे दोगुना करने का वादा हमेशा धोखा है / Money doubling is always a scam", 5),
        "दोगुना": ("पैसे दोगुना स्कीम धोखाधड़ी है / Double money scheme is fraud", 5),
        "लॉटरी": ("लॉटरी जीतने के लिए पैसे देना धोखाधड़ी है / Paying to claim lottery is a scam", 5),
        "इनाम": ("इनाम के लिए फीस मांगना धोखाधड़ी है / Asking fees for prize is fraud", 5),
        "जीता": ("जीतने का दावा करके पैसे मांगना धोखा है / Claiming you won and asking money is scam", 4),
        "जीत": ("जीत का झांसा देकर पैसे मांगना धोखा है", 4),
        "तुरंत": ("तुरंत/जल्दी करने का दबाव धोखाधड़ी की निशानी / Urgency pressure is scam sign", 3),
        "जल्दी": ("जल्दी करने का दबाव धोखाधड़ी की निशानी है", 3),
        "फौरन": ("फौरन करने का दबाव स्कैम है", 3),
        "ब्लॉक": ("खाता ब्लॉक की धमकी धोखाधड़ी है / Account block threat is scam", 3),
        "बंद": ("खाता बंद की धमकी धोखाधड़ी हो सकती है", 3),
        "प्रोसेसिंग फीस": ("प्रोसेसिंग फीस मांगना लोन स्कैम है / Processing fee demand is loan scam", 4),
        "रजिस्ट्रेशन फीस": ("रजिस्ट्रेशन फीस मांगना धोखाधड़ी है", 4),
        "एडवांस": ("एडवांस पेमेंट मांगना धोखाधड़ी हो सकती है", 3),
        "गारंटी रिटर्न": ("गारंटी रिटर्न का वादा हमेशा धोखा है / Guaranteed return is always scam", 5),
        "गारंटीड": ("गारंटीड रिटर्न हमेशा धोखाधड़ी है", 5),
        "ट्रेडिंग": ("ट्रेडिंग में पैसे लगाने का ऑफर धोखा हो सकता है", 4),
        "शेयर": ("शेयर टिप्स देकर पैसे मांगना धोखा हो सकता है", 3),
        "क्रिप्टो": ("क्रिप्टो निवेश में धोखाधड़ी बहुत आम है", 4),
        "बिटकॉइन": ("बिटकॉइन स्कीम में सावधान रहें", 4),
        "वर्क फ्रॉम होम": ("वर्क फ्रॉम होम में पैसे मांगना धोखा है", 3),
        "घर बैठे कमाएं": ("घर बैठे कमाने का झांसा अक्सर धोखा होता है", 4),
        "रिफंड": ("फर्जी रिफंड कॉल से सावधान", 3),
        "otp": ("OTP मांगना धोखाधड़ी है / Asking for OTP is fraud", 5),
        "ओटीपी": ("OTP किसी को न दें - यह धोखाधड़ी है", 5),
        "पिन": ("PIN मांगना बैंक कभी नहीं करता - धोखाधड़ी है", 5),
        "कस्टम": ("कस्टम ड्यूटी मांगना फर्जी डिलीवरी स्कैम है", 4),
        "डिलीवरी चार्ज": ("अनजान डिलीवरी चार्ज स्कैम हो सकता है", 3),
    }

    for keyword, (reason, score) in high_risk_keywords.items():
        if keyword in purpose_lower:
            risk_factors.append(f"🚨 Risky keyword '{keyword}': {reason}")
            risk_score += score

    # Recipient risk assessment
    recipient_lower = recipient.lower().strip()

    # Check if it's a phone number (new/unknown)
    phone_pattern = re.match(r'^[\+]?[0-9]{10,13}$', re.sub(r'[\s\-]', '', recipient_lower))
    if phone_pattern:
        risk_factors.append("Recipient is a phone number - verify if you know this person")
        risk_score += 2

    # Check for UPI IDs with suspicious patterns
    if '@' in recipient_lower:
        suspicious_upi_patterns = ['luck', 'prize', 'winner', 'cash', 'earn', 'profit']
        for pattern in suspicious_upi_patterns:
            if pattern in recipient_lower:
                risk_factors.append(f"Suspicious UPI ID contains '{pattern}'")
                risk_score += 2
                break

    # Cap at 10
    risk_score = min(risk_score, 10)

    # Determine risk level
    if risk_score >= 8:
        risk_level = "CRITICAL"
        recommendation = "DO NOT PROCEED - This shows multiple scam indicators. Consult family first."
    elif risk_score >= 6:
        risk_level = "HIGH"
        recommendation = "WAIT - Get family approval before proceeding. This transaction has significant risk."
    elif risk_score >= 4:
        risk_level = "MEDIUM"
        recommendation = "CAUTION - Verify the recipient and purpose before proceeding."
    else:
        risk_level = "LOW"
        recommendation = "Appears safe - but always double-check recipient details."

    # Determine if family approval needed
    needs_family_approval = risk_score >= 5 or amount >= 5000

    return {
        "status": "success",
        "transaction": {
            "amount": amount,
            "amount_formatted": f"₹{amount:,.0f}",
            "recipient": recipient,
            "purpose": purpose
        },
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "recommendation": recommendation,
        "needs_family_approval": needs_family_approval,
        "family_approval_reason": "High risk score" if risk_score >= 5 else "Amount exceeds ₹5,000" if amount >= 5000 else None
    }


def check_recipient_history(recipient: str) -> dict:
    """Checks if a recipient has been transacted with before (simulated).

    Args:
        recipient: Phone number, UPI ID, or name of the recipient.

    Returns:
        dict: Recipient history and trust assessment.
    """
    recipient_clean = recipient.strip().lower()

    # Simulated known safe recipients (family) - English + Hindi
    known_safe = {
        # English
        "daughter": {"name": "Daughter / बेटी", "trust": "HIGH", "previous_transactions": 45},
        "son": {"name": "Son / बेटा", "trust": "HIGH", "previous_transactions": 38},
        "wife": {"name": "Wife / पत्नी", "trust": "HIGH", "previous_transactions": 120},
        "husband": {"name": "Husband / पति", "trust": "HIGH", "previous_transactions": 95},
        "mother": {"name": "Mother / माँ", "trust": "HIGH", "previous_transactions": 30},
        "father": {"name": "Father / पिताजी", "trust": "HIGH", "previous_transactions": 25},
        "brother": {"name": "Brother / भाई", "trust": "HIGH", "previous_transactions": 20},
        "sister": {"name": "Sister / बहन", "trust": "HIGH", "previous_transactions": 18},
        # Hindi
        "बेटी": {"name": "बेटी / Daughter", "trust": "HIGH", "previous_transactions": 45},
        "बेटा": {"name": "बेटा / Son", "trust": "HIGH", "previous_transactions": 38},
        "पत्नी": {"name": "पत्नी / Wife", "trust": "HIGH", "previous_transactions": 120},
        "पति": {"name": "पति / Husband", "trust": "HIGH", "previous_transactions": 95},
        "माँ": {"name": "माँ / Mother", "trust": "HIGH", "previous_transactions": 30},
        "मां": {"name": "माँ / Mother", "trust": "HIGH", "previous_transactions": 30},
        "पिताजी": {"name": "पिताजी / Father", "trust": "HIGH", "previous_transactions": 25},
        "पापा": {"name": "पापा / Father", "trust": "HIGH", "previous_transactions": 25},
        "भाई": {"name": "भाई / Brother", "trust": "HIGH", "previous_transactions": 20},
        "बहन": {"name": "बहन / Sister", "trust": "HIGH", "previous_transactions": 18},
        "दीदी": {"name": "दीदी / Elder Sister", "trust": "HIGH", "previous_transactions": 15},
        "भैया": {"name": "भैया / Elder Brother", "trust": "HIGH", "previous_transactions": 22},
        # Common terms
        "beti": {"name": "Daughter / बेटी", "trust": "HIGH", "previous_transactions": 45},
        "beta": {"name": "Son / बेटा", "trust": "HIGH", "previous_transactions": 38},
        "mummy": {"name": "Mother / माँ", "trust": "HIGH", "previous_transactions": 30},
        "papa": {"name": "Father / पापा", "trust": "HIGH", "previous_transactions": 25},
        "bhai": {"name": "Brother / भाई", "trust": "HIGH", "previous_transactions": 20},
        "didi": {"name": "Elder Sister / दीदी", "trust": "HIGH", "previous_transactions": 15},
    }

    # Check if known
    for key, info in known_safe.items():
        if key in recipient_clean:
            return {
                "status": "success",
                "recipient": recipient,
                "is_known": True,
                "trust_level": info["trust"],
                "relationship": info["name"],
                "previous_transactions": info["previous_transactions"],
                "verdict": "TRUSTED - Known family member"
            }

    # Unknown recipient
    return {
        "status": "success",
        "recipient": recipient,
        "is_known": False,
        "trust_level": "UNKNOWN",
        "relationship": None,
        "previous_transactions": 0,
        "verdict": "UNKNOWN - Never sent money to this recipient before. Extra caution advised."
    }


def simulate_family_notification(transaction_details: dict, nominee_name: str = "Family Member") -> dict:
    """Simulates sending a notification to family nominee for approval.

    Args:
        transaction_details: The transaction risk assessment details.
        nominee_name: Name of the family nominee to notify (default: Family Member).

    Returns:
        dict: Notification status and approval request details.
    """
    amount = transaction_details.get("transaction", {}).get("amount_formatted", "Unknown")
    recipient = transaction_details.get("transaction", {}).get("recipient", "Unknown")
    purpose = transaction_details.get("transaction", {}).get("purpose", "Unknown")
    risk_level = transaction_details.get("risk_level", "UNKNOWN")
    risk_score = transaction_details.get("risk_score", 0)

    # Generate notification message
    notification_message = f"""
🔔 **Transaction Approval Request**

{nominee_name}, your family member wants to make a payment:

**Amount:** {amount}
**To:** {recipient}
**Purpose:** {purpose}

**AI Risk Assessment:** {risk_level} ({risk_score}/10)

**Risk Factors:**
"""
    for factor in transaction_details.get("risk_factors", []):
        notification_message += f"• {factor}\n"

    notification_message += f"""
**Recommendation:** {transaction_details.get("recommendation", "Review carefully")}

**Your Options:**
✅ APPROVE - Allow this transaction
❌ REJECT - Block this transaction
📞 CALL - Speak to family member first
"""

    return {
        "status": "success",
        "notification_sent": True,
        "nominee_name": nominee_name,
        "notification_message": notification_message,
        "awaiting_response": True,
        "approval_options": ["APPROVE", "REJECT", "CALL_FIRST"],
        "message_to_user": f"📱 {nominee_name} has been notified about this transaction and will review it. Please wait for their response before proceeding.",
        "hindi_message": f"📱 {nominee_name} को इस लेनदेन के बारे में सूचित कर दिया गया है। कृपया आगे बढ़ने से पहले उनकी प्रतिक्रिया का इंतज़ार करें।"
    }
