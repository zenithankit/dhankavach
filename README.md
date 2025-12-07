# DhanKavach - Financial Protection Agent

> **Dhan** (Wealth) + **Kavach** (Shield)
> Protecting the elderly from financial fraud through family-powered AI protection

## Overview

DhanKavach is a multi-agent AI system built with Google's Agent Development Kit (ADK) that protects elderly users from financial scams. It breaks the entire scam chain - from suspicious documents to fraudulent payments - with family members in the loop for approval.

## Features

### Core Agents
- **Document Analyzer Agent** - Analyzes PDFs and documents for fake loan offers, fraudulent schemes
- **Scam Detector Agent** - Detects scam patterns in SMS, WhatsApp messages, emails
- **Transaction Safety Agent** - Pre-payment risk assessment with family approval workflow
- **Advisor Agent** - Synthesizes information and provides actionable guidance

### Key Capabilities
- Connected Intelligence: Links flagged documents to payment attempts
- Family-in-the-loop approval for high-risk transactions
- Phone number reputation checking against scam databases
- RBI registration verification for financial companies
- Visible agent reasoning showing decision-making process
- Support for Hindi and English

## Setup

### Prerequisites
- Python 3.11+
- Google ADK (`pip install google-adk`)
- Either:
  - Ollama with `qwen3:14b` model (local)
  - Google API key for Gemini (cloud)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dhankavach.git
cd dhankavach

# Install dependencies
pip install -r requirements.txt

# For Ollama (local):
export DHANKAVACH_MODEL=ollama
# Make sure Ollama is running with qwen3:14b

# For Gemini (cloud):
export DHANKAVACH_MODEL=gemini
export GOOGLE_API_KEY=your-api-key
```

### Running

```bash
# Start the ADK web interface
adk web . --port 8888 --host 0.0.0.0
```

Then open http://localhost:8888 in your browser.

## Demo Scenarios

### Scenario 1: Complete Scam Chain Detection
1. Upload a fake loan document
2. Agent flags it as fraudulent and saves to risk profile
3. Later, try to pay "processing fee" to a number from the document
4. Agent blocks the payment by connecting it to the flagged document
5. Family member is notified for approval

### Scenario 2: Scam Message Detection
```
User: "Is this message safe? - Your SBI account will be blocked. Update KYC now: bit.ly/sbi-kyc"

DhanKavach: Risk Score 9/10 - KYC SCAM detected
- Fake urgency ("will be blocked")
- Suspicious shortened URL
- Impersonating bank authority
```

### Scenario 3: Transaction Safety
```
User: "I want to send Rs 50,000 to 9876543210 for investment"

DhanKavach:
- Risk Score: 8/10
- Flags: New recipient, "investment" keyword, high amount
- Family approval: REQUIRED
- Nominee notified with full context
```

## Architecture

```
┌─────────────────────┐
│   DhanKavach Core   │
│ (Orchestrator Agent)│
└──────────┬──────────┘
           │
    ┌──────┼──────┐
    │      │      │
    ▼      ▼      ▼
┌────────┐ ┌────────┐ ┌────────┐
│Document│ │  Scam  │ │Advisor │
│Analyzer│ │Detector│ │ Agent  │
└────────┘ └────────┘ └────────┘
    │           │
    ▼           ▼
┌────────┐ ┌────────┐
│ Legal  │ │ Family │
│Checker │ │Alerter │
└────────┘ └────────┘
```

## Model Configuration

Set `DHANKAVACH_MODEL` environment variable:
- `ollama` - Uses local Ollama with qwen3:14b (default)
- `gemini` - Uses Google Gemini 2.0 Flash

## License

MIT License - Built for [Hackathon Name]

## Team

Built with care for protecting our elders from financial fraud.
