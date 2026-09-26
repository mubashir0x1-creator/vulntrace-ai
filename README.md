# VulnTrace AI

Evidence-first security finding triage, AI-assisted analysis, remediation verification, and human-controlled resolution.

## Overview

VulnTrace AI is a Flask + SQLite cybersecurity application designed to transform structured security reports into actionable security findings.

The system combines deterministic security analysis with a local AI analysis layer powered by Ollama and Qwen 2.5 1.5B.

The deterministic security engine remains the source of truth for risk scoring, evidence quality, severity, and finding prioritization. The AI layer provides advisory assistance for understanding findings, explaining potential impact, identifying possible root causes, suggesting remediation, and providing verification guidance.

## Workflow

Security Report
↓
JSON Parser
↓
Finding Normalization
↓
Deterministic Security Analysis
↓
Evidence Quality + Risk Score
↓
Duplicate Detection
↓
SQLite Storage
↓
Dashboard / Reports / Triage
↓
Local Qwen AI Analysis
↓
Remediation
↓
Verification Evidence
↓
Needs Review
↓
Human Resolution

## Core Features

- JSON security report import
- Finding parsing and normalization
- Deterministic risk scoring
- Evidence quality assessment
- Confidence tracking
- Duplicate detection and grouping
- Security triage queue
- Finding detail pages
- Local AI analysis using Ollama and Qwen
- Cached AI analysis
- Remediation guidance
- Verification evidence submission
- Needs Review workflow
- Human-controlled resolution
- SQLite database storage
- User registration and authentication

## Deterministic Security Analysis

VulnTrace AI uses deterministic application logic to analyze security findings.

The system tracks:

- Severity
- Confidence
- Evidence quality
- Risk score
- Duplicate groups
- Finding priority

The deterministic engine remains independent from the AI layer.

This allows the core security analysis to remain reproducible and auditable.

## Local AI Layer

VulnTrace AI uses a locally running Qwen model through Ollama.

Model:

Qwen 2.5 1.5B

Runtime:

Ollama

The AI layer provides:

- Finding summary
- Potential impact
- Root-cause interpretation
- Remediation guidance
- Verification guidance
- AI confidence

The AI layer is designed to avoid:

- Inventing evidence
- Inventing affected assets
- Changing the deterministic risk score
- Claiming unsupported vulnerabilities
- Automatically resolving security findings

## AI Caching

Finding-level AI analysis is cached in the SQLite database.

Cached analyses use:

- analysis_type = finding_ai
- source = ollama

Caching prevents the local AI model from running every time the same finding is opened.

The project also includes a pre_cache_ai.py script that can generate missing AI analyses before a demonstration.

Run:

    python pre_cache_ai.py

## Remediation and Verification

VulnTrace AI separates remediation from verification.

A finding follows this lifecycle:

OPEN
↓
Submit Verification Evidence
↓
NEEDS REVIEW
↓
Human Review
↓
RESOLVED

AI does not automatically resolve findings.

A user must submit verification evidence and explicitly resolve the finding after review.

Verification information is stored in SQLite to maintain an auditable history.

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- Jinja Templates
- Werkzeug
- Ollama
- Qwen 2.5 1.5B

## Project Structure

    .
    ├── app.py
    ├── helpers.py
    ├── requirements.txt
    ├── pre_cache_ai.py
    ├── .gitignore
    │
    ├── database/
    │   ├── schema.sql
    │   └── vulntrace.db
    │
    ├── sample_reports/
    │   └── demo_report.json
    │
    ├── services/
    │   ├── ai_analyzer.py
    │   ├── analyzer.py
    │   └── parser.py
    │
    ├── static/
    │   └── styles.css
    │
    └── templates/
        ├── dashboard.html
        ├── finding.html
        ├── index.html
        ├── layout.html
        ├── login.html
        ├── register.html
        ├── report.html
        ├── reports.html
        ├── triage.html
        └── upload.html

## Installation

Create a Python virtual environment:

    python -m venv .venv

Activate the environment:

    source .venv/bin/activate

Install the required dependencies:

    pip install -r requirements.txt

## Configuration

Set the Flask secret key as an environment variable:

    export VULNTRACE_SECRET_KEY="your-local-secret"

Do not commit the secret key to the repository.

## Ollama Setup

Install Ollama and pull the required model:

    ollama pull qwen2.5:1.5b

Start the Ollama server:

    ollama serve

## Running the Application

Start the Flask application:

    python app.py

Then open the application in a browser:

    http://127.0.0.1:5000

## Pre-Caching AI Analysis

Before a demonstration, missing AI analyses can be generated using:

    python pre_cache_ai.py

Already cached findings are skipped.

## Demonstration Flow

A typical demonstration can follow this sequence:

1. Open the Dashboard.
2. Review security assessment statistics.
3. Open the Triage queue.
4. Select a high-priority finding.
5. Review the finding description and evidence.
6. Review severity, confidence, evidence quality, and risk score.
7. Review duplicate information.
8. View the local Qwen AI analysis.
9. Review remediation guidance.
10. Submit verification evidence.
11. Review the NEEDS REVIEW state.
12. Review the verification information.
13. Explicitly resolve the finding.
14. Confirm the final RESOLVED state.

## Security Design Principles

### Evidence First

Security analysis should be grounded in the evidence supplied by the security report.

### Deterministic Risk

Risk scoring and evidence-related calculations are handled by deterministic application logic.

### AI as an Advisory Layer

AI assists with interpretation and remediation guidance but does not replace the deterministic security analysis engine.

### Human-Controlled Resolution

AI does not automatically close security findings. Resolution requires explicit human action.

### Auditable Workflow

Finding analysis and verification information are persisted in SQLite so that the workflow can be reviewed later.

## Goal

VulnTrace AI demonstrates how deterministic cybersecurity analysis and local AI assistance can work together in an evidence-first security workflow.

The project connects:

Finding → Understanding → Remediation → Verification → Resolution

while keeping important security decisions deterministic, auditable, and under human control.
