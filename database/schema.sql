-- VulnTrace AI database schema.

-- The project architecture, design decisions, testing, and final
-- implementation decisions are the student's own work.

PRAGMA foreign_keys = ON;

-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- REPORTS
-- =========================================================

CREATE TABLE reports (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
name TEXT NOT NULL,
source_format TEXT NOT NULL,
uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (user_id)
REFERENCES users(id)
);

-- =========================================================
-- FINDINGS
-- =========================================================

CREATE TABLE findings (
id INTEGER PRIMARY KEY AUTOINCREMENT,
report_id INTEGER NOT NULL,

title TEXT NOT NULL,
severity TEXT NOT NULL,
confidence REAL,

description TEXT,
evidence TEXT,
asset TEXT,

status TEXT NOT NULL DEFAULT 'open',
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

-- Deterministic evidence and risk analysis.
evidence_quality REAL,
risk_score REAL,

-- Duplicate detection and grouping.
duplicate_key TEXT,
duplicate_of INTEGER,
duplicate_count INTEGER DEFAULT 0,

-- Evidence-based remediation verification.
verification_status TEXT NOT NULL DEFAULT 'not_started',
verification_evidence TEXT,
verified_at TIMESTAMP,

FOREIGN KEY (report_id)
    REFERENCES reports(id)
    ON DELETE CASCADE,

FOREIGN KEY (duplicate_of)
    REFERENCES findings(id)

);

-- =========================================================
-- AI / ANALYSIS RESULTS
-- =========================================================

CREATE TABLE analyses (
id INTEGER PRIMARY KEY AUTOINCREMENT,

finding_id INTEGER NOT NULL,
analysis_type TEXT NOT NULL,
content TEXT NOT NULL,
source TEXT NOT NULL,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

FOREIGN KEY (finding_id)
    REFERENCES findings(id)
    ON DELETE CASCADE

);

-- =========================================================
-- REMEDIATION GUIDANCE
-- =========================================================

CREATE TABLE remediation (
id INTEGER PRIMARY KEY AUTOINCREMENT,

finding_id INTEGER NOT NULL,
recommendation TEXT NOT NULL,
verification TEXT,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

FOREIGN KEY (finding_id)
    REFERENCES findings(id)
    ON DELETE CASCADE

);

-- =========================================================
-- VERIFICATION HISTORY
-- =========================================================

CREATE TABLE verifications (
id INTEGER PRIMARY KEY AUTOINCREMENT,

finding_id INTEGER NOT NULL,

evidence TEXT NOT NULL,
result TEXT NOT NULL DEFAULT 'NEEDS_REVIEW',
ai_assessment TEXT,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

FOREIGN KEY (finding_id)
    REFERENCES findings(id)
    ON DELETE CASCADE

);

-- =========================================================
-- INDEXES
-- =========================================================

CREATE INDEX idx_reports_user_id
ON reports(user_id);

CREATE INDEX idx_findings_report_id
ON findings(report_id);

CREATE INDEX idx_findings_severity
ON findings(severity);

CREATE INDEX idx_findings_duplicate_key
ON findings(duplicate_key);

CREATE INDEX idx_findings_verification_status
ON findings(verification_status);

CREATE INDEX idx_analyses_finding_id
ON analyses(finding_id);

CREATE INDEX idx_remediation_finding_id
ON remediation(finding_id);

CREATE INDEX idx_verifications_finding_id
ON verifications(finding_id);
