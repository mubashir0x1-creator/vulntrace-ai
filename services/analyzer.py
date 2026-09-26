# VulnTrace AI - deterministic security analysis engine.
#
# AI assistance: ChatGPT was used to help draft the initial structure
# of this analysis module.
#
# The scoring model, thresholds, feature decisions, and final implementation
# are the student's own work.

import re
from typing import Any


SEVERITY_WEIGHT = {
    "critical": 95,
    "high": 80,
    "medium": 60,
    "low": 35,
    "informational": 10,
}


def normalize_text(value: Any) -> str:
    """Normalize text for comparison and duplicate detection."""

    if not isinstance(value, str):
        return ""

    value = value.lower().strip()

    value = re.sub(r"\s+", " ", value)

    value = re.sub(r"[^a-z0-9:/._ -]", "", value)

    return value


def build_duplicate_key(
    title: str,
    asset: str,
) -> str:
    """
    Build a conservative duplicate key.

    Findings are considered candidates for duplication when their
    normalized title and asset match.
    """

    normalized_title = normalize_text(title)
    normalized_asset = normalize_text(asset)

    return f"{normalized_title}|{normalized_asset}"


def calculate_evidence_quality(
    evidence: str,
    description: str,
    asset: str,
) -> float:
    """
    Estimate evidence quality using deterministic signals.

    This is not a real-world CVSS calculation. It is a transparent
    project-specific heuristic used to prioritize findings.
    """

    score = 0.0

    if evidence:
        score += 0.55

        if len(evidence) >= 40:
            score += 0.15

        if len(evidence) >= 120:
            score += 0.10

    if description:
        score += 0.10

    if asset:
        score += 0.10

    return min(score, 1.0)


def calculate_risk_score(
    severity: str,
    confidence: float | None,
    evidence_quality: float,
    asset: str,
) -> float:
    """
    Calculate a transparent 0-100 priority score.

    The score combines:
    - severity
    - confidence
    - evidence quality
    - asset presence
    """

    normalized_severity = severity.lower()

    severity_score = SEVERITY_WEIGHT.get(
        normalized_severity,
        SEVERITY_WEIGHT["informational"],
    )

    if confidence is None:
        confidence_score = 0.50
    else:
        confidence_score = max(
            0.0,
            min(1.0, confidence),
        )

    score = (
        severity_score * 0.65
        + confidence_score * 100 * 0.15
        + evidence_quality * 100 * 0.15
    )

    if asset:
        score += 5

    return round(min(score, 100.0), 1)


def priority_label(score: float) -> str:
    """Convert a numeric risk score into a priority label."""

    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"

    return "informational"


def analyze_findings(findings: list[dict]) -> list[dict]:
    """
    Add deterministic analysis data to normalized findings.
    """

    analyzed = []

    for finding in findings:

        evidence = finding.get("evidence", "")
        description = finding.get("description", "")
        asset = finding.get("asset", "")

        evidence_quality = calculate_evidence_quality(
            evidence=evidence,
            description=description,
            asset=asset,
        )

        risk_score = calculate_risk_score(
            severity=finding["severity"],
            confidence=finding["confidence"],
            evidence_quality=evidence_quality,
            asset=asset,
        )

        analyzed.append(
            {
                **finding,
                "evidence_quality": evidence_quality,
                "risk_score": risk_score,
                "priority": priority_label(risk_score),
                "duplicate_key": build_duplicate_key(
                    finding["title"],
                    asset,
                ),
            }
        )

    return analyzed
