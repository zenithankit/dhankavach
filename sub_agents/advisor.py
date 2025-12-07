"""Financial Safety Advisor Agent for DhanKavach."""

from google.adk.agents import Agent

from ..config import get_model
from ..tools import get_safety_tips

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


def create_advisor_agent():
    """Creates and returns the advisor agent."""
    model = get_model()
    return Agent(
        name="advisor",
        model=model,
        description="Provides simple financial safety guidance. Supports English and Hindi.",
        instruction=ADVISOR_INSTRUCTION,
        tools=[get_safety_tips]
    )
