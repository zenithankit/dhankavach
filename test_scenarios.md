# DhanKavach Test Scenarios

Use these scenarios to test the major features of DhanKavach. Copy and paste the user inputs into the chat interface.

---

## Scenario 1: Scam Message Detection (SMS/WhatsApp)

**Purpose:** Test the scam detector agent's ability to identify common scam patterns.

### Test Input:
```
Is this message safe?

"Dear Customer, Your SBI account will be blocked within 24 hours due to incomplete KYC. Click here to update now: http://sbi-kyc-update.xyz/verify. Call 9876543210 for help. - SBI Team"
```

### Expected Behavior:
- Routes to `scam_detector` agent
- Identifies multiple red flags:
  - Urgency ("within 24 hours", "will be blocked")
  - Authority impersonation ("SBI")
  - Suspicious URL (.xyz domain, not official SBI)
  - Personal mobile number (not toll-free)
  - KYC scam pattern
- Risk score: 8-10/10
- Verdict: SCAM
- Provides safety tips in English and Hindi

---

## Scenario 2: Fake Loan Document Analysis

**Purpose:** Test document analyzer and risk profile storage (Connected Intelligence).

### Test Input:
```
Someone sent me this loan offer. Is it real?

---
GOLDEN FINANCE INDIA
Pre-Approved Personal Loan - ₹5,00,000

Congratulations! You have been selected for our exclusive 0% interest loan offer!

Features:
- No documentation required
- Instant approval in 5 minutes
- No credit check needed
- Limited time offer - Act now!

To avail this offer, pay processing fee of ₹2,999 to:
UPI: goldenloan@ybl
Phone: 8765432109

This offer expires in 24 hours. Don't miss out!

Contact: Mr. Sharma - 7654321098
---
```

### Expected Behavior:
- Routes to `document_analyzer` agent
- Identifies red flags:
  - No RBI registration
  - 0% interest claim (too good to be true)
  - "No documentation required"
  - Upfront processing fee
  - Urgency tactics
  - Personal mobile numbers
- Risk score: 8-10/10
- Verdict: FRAUDULENT
- **Flags the document** and stores phone numbers (8765432109, 7654321098) and UPI (goldenloan@ybl) for future protection
- Mentions family notification

---

## Scenario 3: Connected Intelligence - Blocking Payment to Flagged Scammer

**Purpose:** Test the Connected Intelligence feature that blocks payments to previously flagged numbers.

> **IMPORTANT:** Run this AFTER Scenario 2 (the fake loan document)

### Test Input:
```
I want to send ₹2,999 to 8765432109 for loan processing fee
```

### Expected Behavior:
- Routes to `transaction_safety` agent
- **CRITICAL:** Detects that 8765432109 was flagged in the previous document
- Shows Connected Intelligence match
- Risk score: 10/10 (CRITICAL)
- Recommendation: BLOCK - Connected to previously flagged scam
- Family notification triggered
- Explains that this number appeared in a fraudulent loan document

---

## Scenario 4: Safe Family Transaction

**Purpose:** Test that legitimate transactions to family members are marked as safe.

### Test Input:
```
I want to send ₹2,000 to my daughter for groceries
```

### Expected Behavior:
- Routes to `transaction_safety` agent
- Recognizes "daughter" as family member
- Risk score: 1-2/10 (LOW)
- No family approval needed
- Verdict: Safe to proceed
- Quick, non-alarming response

---

## Scenario 5: High-Risk Investment Transaction

**Purpose:** Test detection of investment scam keywords and family approval workflow.

### Test Input:
```
I want to transfer ₹50,000 to 9988776655 for a guaranteed return investment scheme. They promised to double my money in 3 months.
```

### Expected Behavior:
- Routes to `transaction_safety` agent
- Identifies multiple high-risk factors:
  - High amount (₹50,000)
  - "Investment" keyword
  - "Guaranteed return" - definite scam indicator
  - "Double money" - classic scam pattern
  - Unknown recipient
- Risk score: 9-10/10 (CRITICAL)
- Recommendation: DO NOT PROCEED
- Family approval: REQUIRED
- Shows visible reasoning panel with signal analysis
- Provides explanation in Hindi

---

## Scenario 6: Financial Safety Tips

**Purpose:** Test the advisor agent for general safety guidance.

### Test Input:
```
What should I know about keeping my UPI PIN safe?
```

### Expected Behavior:
- Routes to `advisor` agent
- Provides relevant UPI safety tips:
  - Never share PIN with anyone
  - Banks never ask for PIN
  - To receive money, no PIN needed
  - Don't scan QR codes to receive
- Tips in both English and Hindi
- Clear, elderly-friendly language

---

## Bonus Scenario: Hindi Language Support

**Purpose:** Test Hindi language understanding and response.

### Test Input:
```
मुझे यह मैसेज आया है, क्या यह सही है?

"बधाई हो! आपने ₹10 लाख की लॉटरी जीती है। अपना इनाम पाने के लिए ₹5000 रजिस्ट्रेशन फीस भेजें: 9876543210"
```

### Expected Behavior:
- Understands Hindi input
- Detects lottery scam pattern
- Identifies:
  - Prize/lottery scam
  - Registration fee request
  - Phone number for payment
- Risk score: 9-10/10
- Response includes Hindi explanation
- Clear warning about lottery scams

---

## Testing Checklist

| Scenario | Feature Tested | Status |
|----------|---------------|--------|
| 1 | Scam message detection | ⬜ |
| 2 | Document analysis + flagging | ⬜ |
| 3 | Connected Intelligence (payment blocking) | ⬜ |
| 4 | Safe family transactions | ⬜ |
| 5 | High-risk transaction + family approval | ⬜ |
| 6 | Safety tips/advisor | ⬜ |
| Bonus | Hindi language support | ⬜ |

---

## Demo Script for Judges

**Recommended order for maximum impact:**

1. **Start with greeting** - Say "Hello" to show the welcome message
2. **Scenario 2** - Show fake loan document analysis (document gets flagged)
3. **Scenario 3** - Try to pay the scammer → **BLOCKED!** (Connected Intelligence demo)
4. **Scenario 1** - Show scam SMS detection
5. **Scenario 4** - Show safe family transaction (contrast with blocked scam)
6. **Scenario 5** - Show high-risk investment detection with family approval

This order demonstrates the unique "Connected Intelligence" feature that sets DhanKavach apart.
