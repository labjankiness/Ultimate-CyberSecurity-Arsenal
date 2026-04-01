"""
LLM-based email content analysis via Ollama.

Sends email subject and body to a local Ollama instance to evaluate
phishing tactics, social engineering techniques, and malicious intent.

Usage:
    from llm_analyzer import analyze_content
    result = analyze_content(subject, body_text)
"""

import json
import requests
from typing import Optional


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

SYSTEM_PROMPT = """You are a cybersecurity email analyst specializing in phishing detection.

Analyze the provided email for phishing indicators. Evaluate:

1. **Urgency/Pressure tactics**: "act now", "account suspended", "expires today", deadlines
2. **Authority impersonation**: claiming to be CEO, IT department, bank, government
3. **Grammar and formatting**: spelling errors, inconsistent formatting, generic greetings
4. **Credential/data requests**: asking for passwords, SSN, credit cards, login info
5. **Financial requests**: wire transfers, gift cards, invoice payments, cryptocurrency
6. **Emotional manipulation**: fear ("your account is compromised"), curiosity, greed ("you won")
7. **Link/attachment pressure**: urging clicks on links or opening attachments

You MUST respond with ONLY valid JSON — no markdown, no explanation. Just the raw JSON object.

Required JSON schema:
{
  "phishing_probability": <integer 0-100>,
  "verdict": "Phishing" or "Legitimate" or "Suspicious",
  "tactics_detected": ["<tactic1>", "<tactic2>"],
  "reasoning": "<2-3 sentence explanation>",
  "confidence": <integer 0-100>,
  "target_type": "<one of: Credential Harvesting, Financial Fraud, Malware Delivery, Data Theft, Legitimate, Unknown>"
}

Rules:
- phishing_probability 0-30: likely legitimate
- phishing_probability 31-60: suspicious, needs investigation
- phishing_probability 61-100: likely phishing
- List ALL social engineering tactics found in tactics_detected
- Be specific in reasoning — cite exact phrases from the email
- Respond ONLY with the JSON object"""


def _parse_llm_json(text: str) -> Optional[dict]:
    """Parse JSON from LLM output, handling common formatting issues."""
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strip markdown fences
    if "```" in text:
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                json_lines.append(line)
        try:
            return json.loads("\n".join(json_lines))
        except json.JSONDecodeError:
            pass

    # Find JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    return None


def _validate_result(data: dict) -> dict:
    """Ensure all required fields exist with correct types."""
    prob = data.get("phishing_probability", 50)
    if not isinstance(prob, int):
        try:
            prob = int(prob)
        except (ValueError, TypeError):
            prob = 50
    prob = max(0, min(100, prob))

    verdict = data.get("verdict", "Suspicious")
    if verdict not in ("Phishing", "Legitimate", "Suspicious"):
        if prob >= 61:
            verdict = "Phishing"
        elif prob <= 30:
            verdict = "Legitimate"
        else:
            verdict = "Suspicious"

    tactics = data.get("tactics_detected", [])
    if not isinstance(tactics, list):
        tactics = []

    confidence = data.get("confidence", 50)
    if not isinstance(confidence, int):
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            confidence = 50

    valid_targets = {
        "Credential Harvesting", "Financial Fraud", "Malware Delivery",
        "Data Theft", "Legitimate", "Unknown",
    }
    target = data.get("target_type", "Unknown")
    if target not in valid_targets:
        target = "Unknown"

    return {
        "phishing_probability": prob,
        "verdict": verdict,
        "tactics_detected": tactics,
        "reasoning": str(data.get("reasoning", "No reasoning provided.")),
        "confidence": confidence,
        "target_type": target,
    }


def analyze_content(subject: str, body: str, max_retries: int = 1) -> dict:
    """Analyze email content using the local LLM for phishing indicators.

    Args:
        subject: Email subject line.
        body: Email body text (plain text preferred).
        max_retries: Number of retry attempts on parse failure.

    Returns:
        Dict with: phishing_probability, verdict, tactics_detected,
        reasoning, confidence, target_type, model_used.
    """
    # Truncate very long bodies to stay within context
    if len(body) > 3000:
        body = body[:3000] + "\n[... truncated ...]"

    email_text = f"SUBJECT: {subject}\n\nBODY:\n{body}"

    payload = {
        "model": MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\nEMAIL TO ANALYZE:\n{email_text}",
        "stream": False,
    }

    for attempt in range(1 + max_retries):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=90)
            response.raise_for_status()
            raw_text = response.json().get("response", "")

            parsed = _parse_llm_json(raw_text)
            if parsed:
                result = _validate_result(parsed)
                result["model_used"] = MODEL
                return result

            if attempt < max_retries:
                payload["prompt"] = (
                    "IMPORTANT: Your previous response was not valid JSON. "
                    "Respond with ONLY a JSON object.\n\n" + payload["prompt"]
                )

        except requests.RequestException as e:
            return {
                "phishing_probability": 50,
                "verdict": "Error",
                "tactics_detected": [],
                "reasoning": f"LLM request failed: {str(e)}",
                "confidence": 0,
                "target_type": "Unknown",
                "model_used": MODEL,
            }

    return {
        "phishing_probability": 50,
        "verdict": "Error",
        "tactics_detected": [],
        "reasoning": "Failed to parse LLM response as JSON after retry.",
        "confidence": 0,
        "target_type": "Unknown",
        "model_used": MODEL,
    }


def analyze_content_offline(subject: str, body: str) -> dict:
    """Heuristic-based content analysis that works without Ollama.

    Uses keyword matching and pattern detection as a fallback when
    the LLM is not available.

    Args:
        subject: Email subject line.
        body: Email body text.

    Returns:
        Same schema as analyze_content.
    """
    text = f"{subject} {body}".lower()
    tactics: list[str] = []
    score = 0

    # Urgency/pressure
    urgency_words = [
        "urgent", "immediately", "act now", "expire", "suspended",
        "limited time", "within 24 hours", "deadline", "final notice",
        "last chance", "account will be closed",
    ]
    for word in urgency_words:
        if word in text:
            tactics.append(f"Urgency: '{word}'")
            score += 8
            break

    # Authority impersonation
    authority_words = [
        "ceo", "cfo", "president", "it department", "security team",
        "human resources", "legal department", "board of directors",
        "internal revenue", "federal",
    ]
    for word in authority_words:
        if word in text:
            tactics.append(f"Authority impersonation: '{word}'")
            score += 10
            break

    # Credential requests
    cred_words = [
        "password", "credential", "login", "sign in", "verify your",
        "confirm your identity", "social security", "ssn", "pin number",
        "security question",
    ]
    for word in cred_words:
        if word in text:
            tactics.append(f"Credential request: '{word}'")
            score += 15
            break

    # Financial requests
    finance_words = [
        "wire transfer", "gift card", "bitcoin", "invoice attached",
        "payment due", "bank account", "routing number", "cryptocurrency",
    ]
    for word in finance_words:
        if word in text:
            tactics.append(f"Financial request: '{word}'")
            score += 12
            break

    # Emotional manipulation
    fear_words = [
        "compromised", "unauthorized access", "breach", "hacked",
        "suspicious activity", "locked out",
    ]
    greed_words = [
        "winner", "congratulations", "prize", "lottery", "inheritance",
        "million dollars",
    ]
    for word in fear_words:
        if word in text:
            tactics.append(f"Fear tactic: '{word}'")
            score += 10
            break
    for word in greed_words:
        if word in text:
            tactics.append(f"Greed tactic: '{word}'")
            score += 10
            break

    # Generic greeting (not personalized)
    generic = ["dear customer", "dear user", "dear account holder", "dear sir/madam"]
    for g in generic:
        if g in text:
            tactics.append("Generic greeting (not personalized)")
            score += 5
            break

    # Link pressure
    link_pressure = ["click here", "click below", "click the link", "open attachment"]
    for lp in link_pressure:
        if lp in text:
            tactics.append(f"Link/attachment pressure: '{lp}'")
            score += 8
            break

    score = min(score, 100)
    if score >= 40:
        verdict = "Phishing"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return {
        "phishing_probability": score,
        "verdict": verdict,
        "tactics_detected": tactics,
        "reasoning": f"Heuristic analysis found {len(tactics)} phishing indicator(s).",
        "confidence": min(50 + len(tactics) * 10, 90),
        "target_type": "Unknown",
        "model_used": "heuristic (offline)",
    }


if __name__ == "__main__":
    subject = "URGENT: Your PayPal account has been suspended"
    body = """Dear Customer,

We have detected suspicious activity on your account. Your account has been
temporarily suspended. Click here to verify your identity and restore access:

http://paypa1.com/verify-account

You must act within 24 hours or your account will be permanently closed.

PayPal Security Team"""

    print("=== Offline Heuristic Analysis ===")
    result = analyze_content_offline(subject, body)
    print(f"Verdict: {result['verdict']}")
    print(f"Phishing Probability: {result['phishing_probability']}%")
    print(f"Tactics: {', '.join(result['tactics_detected'])}")
    print(f"Reasoning: {result['reasoning']}")

    print("\n=== LLM Analysis (requires Ollama) ===")
    try:
        result = analyze_content(subject, body)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Ollama not available: {e}")
