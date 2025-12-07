"""Scam detection tools for DhanKavach."""

import re


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
        "upi": "upi",
        "payment": "upi",
        "gpay": "upi",
        "phonepe": "upi",
        "paytm": "upi",
        "bank": "banking",
        "banking": "banking",
        "account": "banking",
        "loan": "loans",
        "loans": "loans",
        "credit": "loans",
        "kyc": "kyc",
        "pan": "kyc",
        "aadhaar": "kyc",
        "otp": "otp",
        "pin": "otp",
        "scam": "scams",
        "scams": "scams",
        "fraud": "scams",
        "general": "scams"
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
