import json
import urllib.request


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5:1.5b"


def analyze_finding(finding):
    """
    Analyze a VulnTrace finding using a local Ollama model.

    The deterministic VulnTrace risk engine remains the source
    of truth for severity, risk score, evidence quality, etc.

    AI is only used for explanation, root-cause interpretation,
    remediation guidance, and verification guidance.
    """

    prompt = f"""
You are the AI analysis layer of VulnTrace AI,
an evidence-first security finding triage and remediation system.

Analyze ONLY the security information supplied below.

IMPORTANT RULES:
1. Do not invent evidence.
2. Do not invent affected assets.
3. Do not change or recalculate the deterministic risk score.
4. Clearly distinguish supplied evidence from interpretation.
5. If the evidence is insufficient, say so explicitly.
6. Give practical defensive remediation guidance.
7. Give a concrete way to verify whether the issue was fixed.
8. Do not claim that a vulnerability is confirmed if the supplied
   evidence does not support that conclusion.

Return ONLY valid JSON with exactly these fields:

{{
    "summary": "...",
    "impact": "...",
    "root_cause": "...",
    "remediation": "...",
    "verification": "...",
    "confidence": "High|Medium|Low"
}}

VULNTRACE FINDING:
{json.dumps(finding, indent=2, default=str)}
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.loads(response.read().decode("utf-8"))

    except Exception as exc:
        raise RuntimeError(
            f"Could not connect to local Ollama: {exc}"
        ) from exc

    text = result.get("response", "").strip()

    if not text:
        raise RuntimeError("Ollama returned an empty response.")

    try:
        return json.loads(text)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Local AI returned invalid JSON: {text}"
        ) from exc
