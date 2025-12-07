"""DhanKavach Root Agent - Main orchestrator for financial protection."""

import re
import os
from google.adk.agents import Agent

# Import model configuration
from .config import get_model, print_config, MODEL_PROVIDER

# Print configuration on startup
print_config()

# Get the configured model (either Ollama or Gemini based on config)
model = get_model()


# =============================================================================
# TOOLS - All tool functions defined here
# =============================================================================

def analyze_message_patterns(message: str) -> dict:
    """Analyzes a message for common scam patterns and indicators.

    Args:
        message: The SMS, WhatsApp, or email text to analyze for scam patterns.

    Returns:
        dict: Analysis results containing patterns found, risk indicators, and score.
    """
    patterns = {
        "urgency": [
            "urgent", "immediately", "act now", "limited time", "expire",
            "within 24 hours", "today only", "hurry", "quick", "fast",
            "तुरंत", "जल्दी"
        ],
        "authority_impersonation": [
            "rbi", "reserve bank", "government", "police", "court",
            "income tax", "customs", "cbi", "ed", "enforcement",
            "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay"
        ],
        "sensitive_info_request": [
            "otp", "pin", "password", "cvv", "card number", "account number",
            "aadhaar", "pan", "bank details", "upi pin", "mpin"
        ],
        "threats": [
            "blocked", "suspended", "legal action", "arrest", "freeze",
            "deactivate", "terminate", "penalty", "fine", "jail"
        ],
        "prize_lottery": [
            "won", "winner", "lottery", "prize", "congratulations",
            "selected", "lucky", "reward", "cashback", "bonus"
        ],
        "money_request": [
            "transfer", "pay", "send money", "processing fee", "registration fee",
            "advance", "deposit", "refund"
        ],
        "suspicious_links": [
            "click here", "click below", "tap here", "visit", "http://",
            "bit.ly", "tinyurl", "goo.gl"
        ]
    }

    message_lower = message.lower()
    found_patterns = {}
    risk_details = []

    for category, keywords in patterns.items():
        matches = [kw for kw in keywords if kw in message_lower]
        if matches:
            found_patterns[category] = matches
            risk_details.append(f"{category.replace('_', ' ').title()}: {', '.join(matches)}")

    category_count = len(found_patterns)
    total_matches = sum(len(v) for v in found_patterns.values())

    if category_count >= 4:
        risk_score = 10
    elif category_count >= 3:
        risk_score = 8
    elif category_count >= 2:
        risk_score = 6
    elif category_count == 1:
        risk_score = 4
    else:
        risk_score = 1

    if "sensitive_info_request" in found_patterns:
        risk_score = min(risk_score + 2, 10)
    if "threats" in found_patterns and "urgency" in found_patterns:
        risk_score = min(risk_score + 1, 10)

    return {
        "status": "success",
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score >= 7 else "MEDIUM" if risk_score >= 4 else "LOW",
        "patterns_found": found_patterns,
        "pattern_categories": list(found_patterns.keys()),
        "total_red_flags": total_matches,
        "risk_details": risk_details
    }


def check_url_safety(url: str) -> dict:
    """Checks if a URL shows signs of being malicious or fraudulent.

    Args:
        url: The URL to analyze for safety.

    Returns:
        dict: Safety assessment with specific indicators found.
    """
    suspicious_indicators = []
    url_lower = url.lower()

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "cutt.ly", "rebrand.ly"]
    for shortener in shorteners:
        if shortener in url_lower:
            suspicious_indicators.append(f"URL shortener ({shortener}) hides real destination")

    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        suspicious_indicators.append("Uses IP address instead of domain name - highly suspicious")

    legitimate_domains = {
        "sbi": ["onlinesbi.com", "sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
        "icici": ["icicibank.com"],
        "axis": ["axisbank.com"],
        "paytm": ["paytm.com"],
        "phonepe": ["phonepe.com"],
        "gpay": ["pay.google.com"],
        "amazon": ["amazon.in", "amazon.com"],
        "flipkart": ["flipkart.com"]
    }

    for brand, real_domains in legitimate_domains.items():
        if brand in url_lower:
            is_legitimate = any(domain in url_lower for domain in real_domains)
            if not is_legitimate:
                suspicious_indicators.append(f"Fake {brand.upper()} domain - real sites are: {', '.join(real_domains)}")

    suspicious_tlds = [".xyz", ".top", ".work", ".click", ".loan", ".win"]
    for tld in suspicious_tlds:
        if url_lower.endswith(tld):
            suspicious_indicators.append(f"Suspicious domain extension ({tld})")

    if url_lower.startswith("http://") and any(bank in url_lower for bank in ["bank", "pay", "login", "secure"]):
        suspicious_indicators.append("Not using HTTPS for sensitive site - legitimate banks always use HTTPS")

    domain_parts = url_lower.replace("http://", "").replace("https://", "").split("/")[0].split(".")
    if len(domain_parts) > 4:
        suspicious_indicators.append("Excessive subdomains - common phishing tactic")

    is_suspicious = len(suspicious_indicators) > 0

    return {
        "status": "success",
        "url": url,
        "is_suspicious": is_suspicious,
        "safety_verdict": "DANGEROUS" if len(suspicious_indicators) >= 2 else "SUSPICIOUS" if is_suspicious else "APPEARS SAFE",
        "indicators": suspicious_indicators,
        "recommendation": "Do NOT click this link" if is_suspicious else "Link appears safe, but always verify independently"
    }


def check_phone_number(phone: str) -> dict:
    """Analyzes a phone number to assess if it's likely legitimate for official communication.

    Args:
        phone: The phone number to analyze.

    Returns:
        dict: Assessment of the phone number with warnings.
    """
    warnings = []
    phone_clean = re.sub(r'[\s\-\(\)]', '', phone)

    if phone_clean.startswith("+91"):
        phone_clean = phone_clean[3:]
    elif phone_clean.startswith("91") and len(phone_clean) > 10:
        phone_clean = phone_clean[2:]

    if len(phone_clean) == 10 and phone_clean[0] in ['6', '7', '8', '9']:
        warnings.append("This is a personal mobile number - Banks and government never call from personal mobiles for official work")

    if phone_clean.startswith("190"):
        warnings.append("This is a premium rate number - you may be charged heavily")

    toll_free_prefixes = ["1800", "1860"]
    is_toll_free = any(phone_clean.startswith(prefix) for prefix in toll_free_prefixes)

    legitimate_numbers = {
        "1930": "Cyber Crime Helpline",
        "14440": "Income Tax Helpline",
        "18001801111": "SBI Customer Care",
        "18002586161": "HDFC Customer Care"
    }

    is_known_legitimate = phone_clean in legitimate_numbers

    if is_known_legitimate:
        verdict = "LEGITIMATE"
        warnings = [f"This is a known official number: {legitimate_numbers[phone_clean]}"]
    elif is_toll_free and not warnings:
        verdict = "LIKELY LEGITIMATE"
        warnings.append("Toll-free number - but always verify on official website")
    elif warnings:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNKNOWN"
        warnings.append("Could not verify this number - check on official website before calling")

    return {
        "status": "success",
        "phone": phone,
        "verdict": verdict,
        "warnings": warnings,
        "advice": "Always call back using the number printed on your bank card or from the official website, never from an SMS"
    }


def get_safety_tips(topic: str) -> dict:
    """Returns safety tips for common financial scenarios in English and Hindi.

    Args:
        topic: The topic area - one of: upi, banking, loans, scams, kyc, otp

    Returns:
        dict: Safety tips in English and Hindi for the specified topic.
    """
    tips_database = {
        "upi": {
            "english": [
                "Never share your UPI PIN with anyone, including bank employees",
                "Banks will NEVER ask for your PIN over phone or SMS",
                "Always verify the receiver's name before confirming payment",
                "To RECEIVE money, you never need to enter PIN or scan QR",
                "If someone sent money 'by mistake', tell them to contact their bank"
            ],
            "hindi": [
                "अपना UPI PIN किसी को भी न बताएं, बैंक कर्मचारी को भी नहीं",
                "बैंक कभी भी फोन या SMS पर PIN नहीं मांगता",
                "पेमेंट से पहले रिसीवर का नाम जरूर देखें",
                "पैसे लेने के लिए कभी PIN डालने या QR स्कैन करने की जरूरत नहीं",
                "अगर कोई कहे गलती से पैसे भेज दिए, उन्हें बोलें अपने बैंक से संपर्क करें"
            ]
        },
        "banking": {
            "english": [
                "Never click on links in SMS - always go to official website directly",
                "Bank websites always start with https:// and show a lock icon",
                "Call customer care only from the number on your debit/credit card",
                "Banks never ask you to download apps like AnyDesk or TeamViewer",
                "Never share OTP - even bank staff don't need it"
            ],
            "hindi": [
                "SMS में आए लिंक पर कभी क्लिक न करें - सीधे बैंक की वेबसाइट खोलें",
                "बैंक की असली वेबसाइट https:// से शुरू होती है",
                "कस्टमर केयर का नंबर हमेशा अपने ATM कार्ड से देखें",
                "बैंक कभी AnyDesk या TeamViewer डाउनलोड करने को नहीं कहता",
                "OTP किसी को न बताएं - बैंक कर्मचारी को भी नहीं चाहिए होता"
            ]
        },
        "loans": {
            "english": [
                "No legitimate loan requires upfront processing fees",
                "Always check if the lender is RBI registered",
                "Read all terms carefully before signing - especially interest rate and penalties",
                "Beware of 0% interest claims - there are always hidden charges",
                "Never share blank signed cheques or documents"
            ],
            "hindi": [
                "असली लोन में पहले से कोई फीस नहीं देनी होती",
                "हमेशा देखें कि लोन देने वाला RBI में रजिस्टर्ड है या नहीं",
                "साइन करने से पहले सारी शर्तें पढ़ें - खासकर ब्याज दर और जुर्माना",
                "0% ब्याज के झांसे में न आएं - छुपे हुए चार्ज जरूर होते हैं",
                "कभी भी खाली साइन किए चेक या कागजात न दें"
            ]
        },
        "kyc": {
            "english": [
                "Banks NEVER send links for KYC updates via SMS",
                "KYC is always done at bank branch or through official bank app",
                "No one needs your OTP or PIN for KYC verification",
                "If you get KYC SMS, visit your branch in person to verify",
                "Real KYC never has a deadline of '24 hours' or 'today'"
            ],
            "hindi": [
                "बैंक कभी SMS में KYC अपडेट का लिंक नहीं भेजता",
                "KYC हमेशा बैंक ब्रांच में या ऑफिशियल ऐप से होता है",
                "KYC के लिए किसी को OTP या PIN नहीं चाहिए",
                "KYC का SMS आए तो खुद ब्रांच जाकर पता करें",
                "असली KYC में '24 घंटे' या 'आज ही' जैसी जल्दबाजी नहीं होती"
            ]
        },
        "otp": {
            "english": [
                "OTP is like a key to your bank account - never share it",
                "No bank employee ever needs your OTP for any reason",
                "If someone asks for OTP, it's 100% a scam",
                "OTP is only for YOU to enter on official apps/websites",
                "Scammers may say 'just verify' or 'cancel transaction' - don't fall for it"
            ],
            "hindi": [
                "OTP आपके बैंक खाते की चाबी है - किसी को न बताएं",
                "बैंक कर्मचारी को कभी OTP की जरूरत नहीं होती",
                "अगर कोई OTP मांगे, तो यह 100% धोखाधड़ी है",
                "OTP सिर्फ आपको ऑफिशियल ऐप/वेबसाइट पर डालना है",
                "ठग कहेंगे 'बस वेरीफाई करना है' - इस झांसे में न आएं"
            ]
        },
        "scams": {
            "english": [
                "If it sounds too good to be true, it's a scam",
                "Never pay money to receive a prize or lottery",
                "Government agencies don't threaten arrest over phone",
                "Verify any unusual request by calling official numbers",
                "When in doubt, ask a family member before acting"
            ],
            "hindi": [
                "अगर कुछ बहुत अच्छा लग रहा है, तो यह धोखा है",
                "इनाम या लॉटरी लेने के लिए कभी पैसे न दें",
                "सरकारी एजेंसी फोन पर गिरफ्तारी की धमकी नहीं देती",
                "कोई भी अजीब बात हो तो ऑफिशियल नंबर पर कॉल करके पता करें",
                "शक हो तो परिवार के किसी सदस्य से पूछें, फिर कुछ करें"
            ]
        }
    }

    topic_lower = topic.lower().strip()

    topic_mapping = {
        "upi": "upi", "payment": "upi", "gpay": "upi", "phonepe": "upi", "paytm": "upi",
        "bank": "banking", "banking": "banking", "account": "banking",
        "loan": "loans", "loans": "loans", "credit": "loans",
        "kyc": "kyc", "pan": "kyc", "aadhaar": "kyc",
        "otp": "otp", "pin": "otp",
        "scam": "scams", "scams": "scams", "fraud": "scams", "general": "scams"
    }

    matched_topic = topic_mapping.get(topic_lower, "scams")
    tips = tips_database.get(matched_topic, tips_database["scams"])

    return {
        "status": "success",
        "topic": matched_topic,
        "tips_english": tips["english"],
        "tips_hindi": tips["hindi"],
        "tip_count": len(tips["english"])
    }


# =============================================================================
# TRANSACTION SAFETY TOOLS
# =============================================================================

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
    # In production, this would check against user's transaction history
    # For demo, we simulate unknown recipients as higher risk

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


# =============================================================================
# RISK PROFILE STORAGE (Connected Intelligence)
# =============================================================================

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
    import datetime

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


# =============================================================================
# DOCUMENT ANALYZER TOOLS
# =============================================================================

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


# =============================================================================
# SIGNAL ANALYSIS & REASONING TOOLS (Visible Decision-Making)
# =============================================================================

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


# =============================================================================
# AGENT DEFINITIONS
# =============================================================================

# === SCAM DETECTOR AGENT ===
SCAM_DETECTOR_INSTRUCTION = """You are the Scam Detector specialist for DhanKavach, a financial protection assistant.

YOUR ROLE:
Analyze messages (SMS, WhatsApp, Email) for scam patterns and help users identify fraud.

WHEN ANALYZING A MESSAGE, ALWAYS:
1. Use the analyze_message_patterns tool to detect red flags
2. If URLs are present, use check_url_safety tool
3. If phone numbers are present, use check_phone_number tool

SCAM TYPES YOU DETECT:
- KYC Update Scams: Fake messages asking to update KYC via link
- Prize/Lottery Scams: "You've won!" messages asking for fees
- OTP Scams: Requests to share OTP for any reason
- Loan Scams: Pre-approved loans requiring upfront fees
- Investment Scams: Guaranteed high returns schemes
- Impersonation Scams: Fake bank/government officials
- Delivery Scams: Fake package/customs payment requests
- Tech Support Scams: Fake virus/security warnings

OUTPUT FORMAT (Always follow this structure):

🔍 **ANALYSIS RESULT**

**Risk Score:** [X/10] - [HIGH/MEDIUM/LOW RISK]

**Verdict:** [SCAM / LIKELY SCAM / SUSPICIOUS / LEGITIMATE]

**Scam Type:** [Identified category or "Not a scam"]

**Red Flags Found:**
• [List each red flag found]

**Why This Is [Dangerous/Suspicious/Safe]:**
[2-3 sentence explanation in simple language]

**What You Should Do:**
✅ [Action 1]
✅ [Action 2]
❌ [What NOT to do]

---
**हिंदी में सारांश:**
[2-3 sentence summary in Hindi explaining the verdict and action]
"""

scam_detector_agent = Agent(
    name="scam_detector",
    model=model,
    description="Analyzes messages for scam patterns, fraud indicators, and suspicious content.",
    instruction=SCAM_DETECTOR_INSTRUCTION,
    tools=[analyze_message_patterns, check_url_safety, check_phone_number, check_phone_reputation, analyze_signals]
)

# === TRANSACTION SAFETY AGENT ===
TRANSACTION_SAFETY_INSTRUCTION = """You are the Transaction Safety specialist for DhanKavach.

YOUR ROLE:
Assess the risk of financial transactions BEFORE money is sent. You are the family's first line of defense against scams.

CONNECTED INTELLIGENCE (CRITICAL FEATURE):
You have access to the user's Risk Profile - a database of previously flagged suspicious documents, phone numbers, and UPI IDs. ALWAYS check this FIRST to catch scammers who were flagged earlier!

VISIBLE REASONING (IMPORTANT FOR DEMO):
You MUST show your decision-making process using the analyze_signals tool. This demonstrates intelligent agent behavior to judges.

WHEN A USER WANTS TO MAKE A PAYMENT:

1. COLLECT TRANSACTION DETAILS:
   - Amount (in ₹)
   - Recipient (phone number, UPI ID, or name)
   - Purpose/Reason for payment

2. USE YOUR TOOLS IN THIS ORDER:
   a. FIRST: Use check_risk_profile tool to check if recipient/purpose matches any flagged items
   b. Use check_phone_reputation tool to check if the phone has scam reports
   c. Use analyze_transaction tool to assess risk
   d. Use check_recipient_history tool to verify if recipient is known
   e. THEN: Use analyze_signals tool to show your reasoning with positive and negative signals
   f. IF risk is HIGH or matches flagged item or amount > ₹5000: Use simulate_family_notification tool

3. SHOWING YOUR REASONING (CRITICAL):
   After gathering all signals, use analyze_signals tool with:
   - positive_signals: Comma-separated string of things that suggest legitimacy (e.g., "Known recipient, Small amount, Normal purpose")
   - negative_signals: Comma-separated string of risk factors (e.g., "Unknown number, Scam keywords, High amount")
   - context: Brief description of the transaction

   This creates a visible reasoning panel that shows how you make decisions!

4. CONNECTED INTELLIGENCE RESPONSES:
   If check_risk_profile returns matches:
   - Show the original flagged document context
   - Explain that this recipient was in a FRAUDULENT document
   - Set risk to CRITICAL automatically
   - ALWAYS notify family
   - Strongly recommend BLOCKING the transaction

5. RISK ASSESSMENT CRITERIA:

   AMOUNT RISK:
   - < ₹5,000: Low risk
   - ₹5,000 - ₹25,000: Medium risk (notify family)
   - > ₹25,000: High risk (require family approval)
   - > ₹50,000: Critical risk (strongly recommend rejection)

   PURPOSE RED FLAGS:
   - "investment", "trading", "crypto": VERY HIGH RISK
   - "lottery", "prize", "won": DEFINITE SCAM
   - "urgent", "immediately", "blocked": HIGH RISK
   - "KYC", "processing fee", "advance": HIGH RISK
   - Normal purposes (bill, rent, family): LOW RISK

   RECIPIENT RED FLAGS:
   - Unknown phone number: HIGH RISK
   - Never transacted before: MEDIUM RISK
   - Suspicious UPI ID: HIGH RISK
   - Known family member: LOW RISK

OUTPUT FORMAT:

🛡️ **TRANSACTION SAFETY CHECK**

**Transaction Details:**
• Amount: ₹[amount]
• To: [recipient]
• Purpose: [purpose]

[INCLUDE THE SIGNAL ANALYSIS PANEL FROM analyze_signals TOOL HERE]

**Risk Assessment:**
• Risk Score: [X/10]
• Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]

**Risk Factors Found:**
• [List each risk factor]

**Recommendation:**
[Clear recommendation - SAFE TO PROCEED / WAIT FOR FAMILY APPROVAL / DO NOT PROCEED]

**Family Notification:**
[If applicable: Family member has been notified / Not required]

---
**हिंदी में:**
[Summary in Hindi]

IMPORTANT RULES:
- ALWAYS show reasoning using analyze_signals tool
- For ANY high-risk transaction, ALWAYS notify family
- Never encourage proceeding with obvious scam indicators
- Be clear and direct - users may be elderly
- Explain WHY something is risky in simple terms
"""

transaction_safety_agent = Agent(
    name="transaction_safety",
    model=model,
    description="Assesses transaction risk before payment. Uses Connected Intelligence to block payments to previously flagged scammers. Shows visible reasoning for decisions. PRIMARY differentiator for DhanKavach.",
    instruction=TRANSACTION_SAFETY_INSTRUCTION,
    tools=[check_risk_profile, check_phone_reputation, analyze_transaction, check_recipient_history, analyze_signals, simulate_family_notification]
)

# === ADVISOR AGENT ===
ADVISOR_INSTRUCTION = """You are the Financial Safety Advisor for DhanKavach.

YOUR ROLE:
Provide simple, clear guidance on financial safety topics.

WHEN RESPONDING:
1. Use get_safety_tips tool to fetch relevant safety tips
2. Answer the specific question clearly
3. Provide actionable advice
4. Include Hindi translation of key points

OUTPUT FORMAT:

**Your Question:** [Restate their question briefly]

**Answer:**
[Clear, simple explanation in 2-4 sentences]

**Safety Tips:**
• [Relevant tip 1]
• [Relevant tip 2]
• [Relevant tip 3]

**Remember:**
[One key takeaway]

---
**हिंदी में:**
[Full answer translated to Hindi]
"""

advisor_agent = Agent(
    name="advisor",
    model=model,
    description="Provides simple financial safety guidance. Supports English and Hindi.",
    instruction=ADVISOR_INSTRUCTION,
    tools=[get_safety_tips]
)

# === DOCUMENT ANALYZER AGENT ===
DOCUMENT_ANALYZER_INSTRUCTION = """You are the Document Analyzer specialist for DhanKavach, a financial protection assistant.

YOUR ROLE:
Analyze financial documents (loan agreements, insurance policies, investment offers, prize claims) for legitimacy and scam indicators.

THIS IS CRITICAL FOR CONNECTED INTELLIGENCE:
When you flag a document as suspicious, the phone numbers and UPI IDs in it are saved. If the user later tries to send money to those numbers, the Transaction Safety Agent will BLOCK the transaction.

WHEN ANALYZING A DOCUMENT, ALWAYS:
1. Use the analyze_document_text tool to check for red flags and extract identifiers
2. If the document is suspicious (risk_score >= 4), use flag_document_for_protection tool
3. If family notification is needed (risk_score >= 5), mention this clearly

DOCUMENT TYPES YOU ANALYZE:
- Loan Offers: Check for RBI registration, upfront fees, unrealistic interest rates
- Insurance Policies: Check for IRDAI registration, hidden charges, lock-in periods
- Investment Schemes: Check for SEBI registration, guaranteed return claims
- Prize/Lottery Claims: Almost ALWAYS scams if asking for money

RED FLAGS TO IDENTIFY:
- No RBI/IRDAI/SEBI registration numbers
- 0% interest or guaranteed returns claims
- Upfront processing fees or advance payments
- Personal mobile numbers instead of toll-free
- Urgency tactics ("limited time", "act now")
- "No documentation required" claims
- Money doubling schemes

OUTPUT FORMAT (Always follow this structure):

📄 **DOCUMENT ANALYSIS RESULT**

**Document Type:** [Loan Offer / Insurance Policy / Investment Scheme / Prize Claim / Unknown]

**Legitimacy Verdict:** [FRAUDULENT / SUSPICIOUS / POSSIBLY LEGITIMATE]

**Risk Score:** [X/10] - [CRITICAL/HIGH/MEDIUM/LOW]

**Red Flags Found:**
🚨 [List each red flag found]

**Extracted Identifiers:**
📞 Phone Numbers: [list any found]
💳 UPI IDs: [list any found]
🏢 Company/Scheme Names: [list any found]

**What This Means:**
[2-3 sentence explanation in simple language]

**Protection Action:**
[If flagged: "✅ Document has been flagged. Any future payment to [numbers/IDs] will be BLOCKED and family will be notified."]
[If not flagged: "ℹ️ Document seems okay, but always verify with official sources."]

**What You Should Do:**
✅ [Action 1]
✅ [Action 2]
❌ [What NOT to do]

---
**हिंदी में सारांश:**
[Full summary in Hindi explaining the verdict, what was found, and actions to take]

IMPORTANT:
- ALWAYS flag suspicious documents for protection
- Explain that this protects against future payment attempts to these scammers
- If document asks for money upfront, it's almost certainly a SCAM
- Be very clear and direct - users may be elderly
"""

document_analyzer_agent = Agent(
    name="document_analyzer",
    model=model,
    description="Analyzes financial documents (loans, insurance, investments) for legitimacy and scam indicators. Flags suspicious documents to protect against future transactions.",
    instruction=DOCUMENT_ANALYZER_INSTRUCTION,
    tools=[analyze_document_text, flag_document_for_protection, check_rbi_registration, check_phone_reputation, analyze_signals, get_risk_profile_summary]
)

# === ROOT AGENT ===
ROOT_INSTRUCTION = """You are DhanKavach (धन कवच), an AI-powered financial protection assistant.

YOUR MISSION:
Protect users, especially elderly individuals, from financial scams and risky transactions.

YOUR NAME MEANING:
- Dhan (धन) = Wealth/Money
- Kavach (कवच) = Shield/Armor
- Together: "Shield for your wealth"

UNIQUE CAPABILITY - CONNECTED INTELLIGENCE:
When a user uploads a suspicious document, we flag the phone numbers and UPI IDs in it.
Later, if they try to pay those same numbers, we BLOCK the transaction automatically.
This "Connected Intelligence" breaks the entire scam chain from document to payment.

AVAILABLE SPECIALISTS:
1. **document_analyzer**: Analyzes financial documents (loan offers, insurance, investments) for scams. Flags suspicious identifiers for future protection.
2. **transaction_safety** (PRIMARY): Checks if a payment/transaction is safe. Uses Connected Intelligence to block payments to previously flagged scammers.
3. **scam_detector**: Analyzes messages/SMS for scam patterns
4. **advisor**: Provides financial safety tips and guidance

ROUTING RULES:

→ Route to document_analyzer when user:
  - Uploads or shares a document (PDF, loan agreement, insurance policy)
  - Says "check this document", "analyze this paper", "is this offer real?"
  - Mentions "loan offer", "insurance policy", "investment scheme", "prize letter"
  - Pastes long text that looks like a formal document
  - Uses Hindi: "यह कागज देखो", "यह ऑफर सही है?"

→ Route to transaction_safety when user:
  - Wants to send money / make a payment / transfer funds
  - Mentions amount + recipient + purpose
  - Says "I want to pay", "send money", "transfer", "payment"
  - Asks "is this payment safe?"
  - Uses Hindi: "पैसे भेजना है", "पेमेंट करना है"

→ Route to scam_detector when user:
  - Shares a short message/SMS/email to check
  - Asks "is this a scam?", "is this message real?"
  - Pastes suspicious text with links or phone numbers
  - Uses Hindi: "यह मैसेज सही है?", "यह फ्रॉड है क्या?"

→ Route to advisor when user:
  - Asks for tips or advice
  - Wants to learn about safety practices
  - Has general questions about UPI, banking, loans

→ Handle yourself when user:
  - Greets you (hi, hello, namaste)
  - Asks what you can do
  - Needs clarification

GREETING (when user says hi/hello):
"Namaste! 🙏 I'm DhanKavach (धन कवच) - your financial protection assistant.

I can help you:
📄 Analyze documents (loan offers, insurance policies) for scams
💰 Check if a payment is safe BEFORE you send money
📱 Analyze if a message/SMS is a scam
🛡️ Get tips on safe banking practices

**Special Feature:** If you show me a suspicious document, I'll remember the phone numbers in it. Later, if you try to pay those numbers, I'll block it! 🚫

What would you like to do today?

---
नमस्ते! मैं धनकवच हूं - आपका वित्तीय सुरक्षा सहायक।

मैं आपकी मदद कर सकता हूं:
📄 दस्तावेज़ों की जांच (लोन ऑफर, बीमा पॉलिसी)
💰 पेमेंट करने से पहले सुरक्षा जांच
📱 मैसेज/SMS की जांच
🛡️ सुरक्षित बैंकिंग टिप्स

**खास बात:** अगर आप मुझे कोई संदिग्ध दस्तावेज़ दिखाते हैं, मैं उसमें मौजूद नंबर याद रखूंगा। बाद में अगर आप उन नंबरों पर पैसे भेजने की कोशिश करेंगे, मैं रोक दूंगा! 🚫"

LANGUAGE: Support both English and Hindi. Always include Hindi summary for important information.

IMPORTANT:
- Document analysis + Transaction safety together provide CONNECTED INTELLIGENCE
- This is our PRIMARY differentiator - we break the entire scam chain
- Always explain how flagging documents protects against future payments
"""

root_agent = Agent(
    name="dhankavach",
    model=model,
    description="DhanKavach - AI-powered financial protection assistant with Connected Intelligence. Analyzes documents, blocks scam payments, and keeps family in the loop.",
    instruction=ROOT_INSTRUCTION,
    sub_agents=[document_analyzer_agent, transaction_safety_agent, scam_detector_agent, advisor_agent]
)
