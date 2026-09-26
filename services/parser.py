# VulnTrace AI report parser.
#
# AI assistance: ChatGPT was used to help draft the initial parser structure.
# The project requirements, data format, validation rules, and implementation
# decisions are the student's own work.

from typing import Any


ALLOWED_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "informational",
}


def normalize_severity(value: Any) -> str:
    """Return a normalized severity string."""
    if not isinstance(value, str):
        return "informational"

    severity = value.strip().lower()

    if severity not in ALLOWED_SEVERITIES:
        return "informational"

    return severity


def normalize_confidence(value: Any) -> float | None:
    """Convert confidence to a number between 0 and 1."""
    if value is None:
        return None

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None

    if confidence < 0:
        return 0.0

    if confidence > 1:
        return 1.0

    return confidence


def parse_report(data: Any) -> list[dict]:
    """
    Validate and normalize the findings in an uploaded report.

    Expected format:

    {
        "findings": [
            {
                "title": "...",
                "severity": "...",
                "confidence": 0.9,
                "description": "...",
                "evidence": "...",
                "asset": "..."
            }
        ]
    }
    """

    if not isinstance(data, dict):
        raise ValueError("The report must contain a JSON object.")

    raw_findings = data.get("findings")

    if not isinstance(raw_findings, list):
        raise ValueError("The report must contain a 'findings' list.")

    normalized_findings = []

    for number, finding in enumerate(raw_findings, start=1):

        if not isinstance(finding, dict):
            raise ValueError(
                f"Finding #{number} is not a valid object."
            )

        title = finding.get("title")

        if not isinstance(title, str) or not title.strip():
            raise ValueError(
                f"Finding #{number} is missing a title."
            )

        normalized_findings.append(
            {
                "title": title.strip(),
                "severity": normalize_severity(
                    finding.get("severity")
                ),
                "confidence": normalize_confidence(
                    finding.get("confidence")
                ),
                "description": str(
                    finding.get("description", "")
                ).strip(),
                "evidence": str(
                    finding.get("evidence", "")
                ).strip(),
                "asset": str(
                    finding.get("asset", "")
                ).strip(),
            }
        )

    return normalized_findings
