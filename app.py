# VulnTrace AI
#
# AI assistance: ChatGPT was used to help draft and debug parts of the
# initial Flask application, database migration logic, and analysis flow.
#
# The product concept, security model, scoring logic, feature decisions,
# testing, and final implementation decisions are the student's own work.

from pathlib import Path
import json
import os
import sqlite3
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from services.parser import parse_report
from services.analyzer import analyze_findings
from services.ai_analyzer import analyze_finding


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "VULNTRACE_SECRET_KEY"
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "VULNTRACE_SECRET_KEY environment variable is not set."
    )

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent

DATABASE = BASE_DIR / "database" / "vulntrace.db"

DEMO_REPORT = BASE_DIR / "sample_reports" / "demo_report.json"

ALLOWED_EXTENSIONS = {"json"}


# =========================================================
# DATABASE
# =========================================================

def get_db():
    """Open the SQLite database."""

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def ensure_database_schema():
    """
    Add required columns/tables when an older VulnTrace
    database already exists.
    """

    db = get_db()

    columns = {
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(findings)"
        ).fetchall()
    }

    required_columns = {
        "evidence_quality": "REAL DEFAULT 0",
        "risk_score": "REAL DEFAULT 0",
        "duplicate_key": "TEXT",
        "duplicate_of": "INTEGER",
        "duplicate_count": "INTEGER NOT NULL DEFAULT 1",
        "verification_status": (
            "TEXT NOT NULL DEFAULT 'not_started'"
        ),
        "verification_evidence": "TEXT",
        "verified_at": "TIMESTAMP",
    }

    for column_name, column_definition in required_columns.items():

        if column_name not in columns:

            db.execute(
                f"""
                ALTER TABLE findings
                ADD COLUMN {column_name} {column_definition}
                """
            )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            evidence TEXT NOT NULL,
            result TEXT NOT NULL DEFAULT 'NEEDS_REVIEW',
            ai_assessment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (finding_id)
                REFERENCES findings(id)
                ON DELETE CASCADE
        )
        """
    )

    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_verifications_finding_id
        ON verifications(finding_id)
        """
    )

    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_analyses_finding_type_source
        ON analyses(finding_id, analysis_type, source)
        """
    )

    db.commit()

    db.close()


# =========================================================
# AI ANALYSIS CACHE
# =========================================================

def get_cached_ai_analysis(db, finding_id):
    """
    Return the most recent cached finding-level AI analysis.

    This prevents Ollama/Qwen from running every time the
    same finding page is opened.
    """

    row = db.execute(
        """
        SELECT content
        FROM analyses
        WHERE finding_id = ?
        AND analysis_type = 'finding_ai'
        AND source = 'ollama'
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (finding_id,),
    ).fetchone()

    if row is None:
        return None

    try:
        return json.loads(row["content"])

    except (
        TypeError,
        json.JSONDecodeError,
    ):
        return None


def save_ai_analysis(db, finding_id, ai_analysis):
    """
    Store a successful local AI analysis.

    The deterministic VulnTrace risk engine remains the
    source of truth. AI output is advisory.
    """

    db.execute(
        """
        INSERT INTO analyses
        (
            finding_id,
            analysis_type,
            content,
            source
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            finding_id,
            "finding_ai",
            json.dumps(
                ai_analysis,
                ensure_ascii=False,
            ),
            "ollama",
        ),
    )

    db.commit()


# =========================================================
# AUTHENTICATION
# =========================================================

def login_required(view):
    """Require the user to be logged in."""

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            flash("Please log in first.")

            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# =========================================================
# FILE HELPERS
# =========================================================

def allowed_file(filename):
    """Return True when a supported JSON extension is used."""

    return (
        "."
        in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# SAVE REPORT
# =========================================================

def save_report(
    db,
    user_id,
    name,
    source_format,
    findings,
):
    """
    Store a report and its analyzed findings.

    Duplicate findings remain visible for auditability,
    while duplicate candidates point to the first finding
    in their duplicate group.
    """

    cursor = db.execute(
        """
        INSERT INTO reports
            (user_id, name, source_format)
        VALUES (?, ?, ?)
        """,
        (
            user_id,
            name,
            source_format,
        ),
    )

    report_id = cursor.lastrowid

    first_finding_by_key = {}

    group_counts = {}

    inserted_finding_ids = {}

    for finding in findings:

        duplicate_key = finding["duplicate_key"]

        duplicate_of = first_finding_by_key.get(
            duplicate_key
        )

        cursor = db.execute(
            """
            INSERT INTO findings
            (
                report_id,
                title,
                severity,
                confidence,
                description,
                evidence,
                asset,
                status,
                evidence_quality,
                risk_score,
                duplicate_key,
                duplicate_of,
                duplicate_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                finding["title"],
                finding["severity"],
                finding["confidence"],
                finding["description"],
                finding["evidence"],
                finding["asset"],
                "open",
                finding["evidence_quality"],
                finding["risk_score"],
                duplicate_key,
                duplicate_of,
                1,
            ),
        )

        finding_id = cursor.lastrowid

        if duplicate_of is None:

            first_finding_by_key[
                duplicate_key
            ] = finding_id

            inserted_finding_ids[
                duplicate_key
            ] = finding_id

        group_counts[duplicate_key] = (
            group_counts.get(
                duplicate_key,
                0,
            )
            + 1
        )

    for duplicate_key, count in group_counts.items():

        first_id = inserted_finding_ids[
            duplicate_key
        ]

        db.execute(
            """
            UPDATE findings
            SET duplicate_count = ?
            WHERE id = ?
            """,
            (
                count,
                first_id,
            ),
        )

    db.commit()

    return report_id


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():
    """Public landing page."""

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "index.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"],
)
def register():
    """Create a new account."""

    if request.method == "POST":

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        confirmation = request.form.get(
            "confirmation",
            "",
        )

        if not username:

            flash(
                "Username is required."
            )

            return render_template(
                "register.html"
            )

        if not password:

            flash(
                "Password is required."
            )

            return render_template(
                "register.html"
            )

        if password != confirmation:

            flash(
                "Passwords do not match."
            )

            return render_template(
                "register.html"
            )

        password_hash = (
            generate_password_hash(
                password
            )
        )

        db = get_db()

        try:

            cursor = db.execute(
                """
                INSERT INTO users
                    (username, password_hash)
                VALUES (?, ?)
                """,
                (
                    username,
                    password_hash,
                ),
            )

            db.commit()

        except sqlite3.IntegrityError:

            db.close()

            flash(
                "That username is already taken."
            )

            return render_template(
                "register.html"
            )

        user_id = cursor.lastrowid

        db.close()

        session.clear()

        session["user_id"] = user_id

        flash(
            "Account created successfully."
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    """Log an existing user in."""

    if request.method == "POST":

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if not username:

            flash(
                "Username is required."
            )

            return render_template(
                "login.html"
            )

        if not password:

            flash(
                "Password is required."
            )

            return render_template(
                "login.html"
            )

        db = get_db()

        user = db.execute(
            """
            SELECT
                id,
                username,
                password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        db.close()

        if user is None or not check_password_hash(
            user["password_hash"],
            password,
        ):

            flash(
                "Invalid username or password."
            )

            return render_template(
                "login.html"
            )

        session.clear()

        session["user_id"] = user["id"]

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():
    """Log the user out."""

    session.clear()

    return redirect(
        url_for("index")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """Display the security overview."""

    db = get_db()

    user = db.execute(
        """
        SELECT username
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],),
    ).fetchone()

    if user is None:

        db.close()

        session.clear()

        flash(
            "Account not found."
        )

        return redirect(
            url_for("login")
        )

    # =====================================================
    # BASIC COUNTS
    # =====================================================

    report_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM reports
        WHERE user_id = ?
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    finding_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    unique_finding_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND findings.duplicate_of IS NULL
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    # =====================================================
    # SEVERITY COUNTS
    # =====================================================

    critical_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND LOWER(findings.severity) = 'critical'
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    high_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND LOWER(findings.severity) = 'high'
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    # =====================================================
    # VERIFICATION COUNTS
    # =====================================================

    resolved_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND findings.verification_status = 'resolved'
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    needs_review_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND findings.verification_status = 'needs_review'
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    not_started_count = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND (
            findings.verification_status = 'not_started'
            OR findings.verification_status IS NULL
        )
        """,
        (session["user_id"],),
    ).fetchone()["count"]

    # =====================================================
    # TOP PRIORITY FINDINGS
    # =====================================================

    top_findings = db.execute(
        """
        SELECT
            findings.id,
            findings.title,
            findings.severity,
            findings.risk_score,
            findings.asset,
            findings.duplicate_count,
            findings.verification_status
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND findings.duplicate_of IS NULL
        ORDER BY
            CASE
                WHEN findings.verification_status = 'resolved'
                THEN 1
                ELSE 0
            END,
            findings.risk_score DESC,
            findings.id ASC
        LIMIT 5
        """,
        (session["user_id"],),
    ).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        username=user["username"],
        report_count=report_count,
        finding_count=finding_count,
        critical_count=critical_count,
        high_count=high_count,
        unique_finding_count=unique_finding_count,
        resolved_count=resolved_count,
        needs_review_count=needs_review_count,
        not_started_count=not_started_count,
        top_findings=top_findings,
    )


# =========================================================
# REPORTS
# =========================================================

@app.route("/reports")
@login_required
def reports():
    """Display the user's reports."""

    db = get_db()

    report_rows = db.execute(
        """
        SELECT
            reports.id,
            reports.name,
            reports.source_format,
            reports.uploaded_at,
            COUNT(findings.id) AS finding_count,
            COUNT(
                CASE
                    WHEN findings.duplicate_of IS NULL
                    THEN 1
                END
            ) AS unique_finding_count
        FROM reports
        LEFT JOIN findings
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        GROUP BY
            reports.id,
            reports.name,
            reports.source_format,
            reports.uploaded_at
        ORDER BY reports.uploaded_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    db.close()

    return render_template(
        "reports.html",
        reports=report_rows,
    )


# =========================================================
# UPLOAD REPORT
# =========================================================

@app.route(
    "/reports/upload",
    methods=["GET", "POST"],
)
@login_required
def upload_report():
    """Upload and analyze a JSON security report."""

    if request.method == "POST":

        uploaded_file = request.files.get(
            "report"
        )

        if uploaded_file is None:

            flash(
                "Please select a report file."
            )

            return render_template(
                "upload.html"
            )

        if not uploaded_file.filename:

            flash(
                "Please select a report file."
            )

            return render_template(
                "upload.html"
            )

        if not allowed_file(
            uploaded_file.filename
        ):

            flash(
                "Only JSON report files are currently supported."
            )

            return render_template(
                "upload.html"
            )

        safe_name = secure_filename(
            uploaded_file.filename
        )

        if not safe_name:

            flash(
                "The uploaded filename is invalid."
            )

            return render_template(
                "upload.html"
            )

        try:

            data = json.load(
                uploaded_file
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):

            flash(
                "The uploaded file is not valid JSON."
            )

            return render_template(
                "upload.html"
            )

        try:

            findings = parse_report(
                data
            )

            findings = analyze_findings(
                findings
            )

        except ValueError as error:

            flash(str(error))

            return render_template(
                "upload.html"
            )

        if not findings:

            flash(
                "The report contains no findings."
            )

            return render_template(
                "upload.html"
            )

        db = get_db()

        report_id = save_report(
            db=db,
            user_id=session["user_id"],
            name=safe_name,
            source_format="JSON",
            findings=findings,
        )

        db.close()

        duplicate_count = (
            len(findings)
            - len(
                {
                    finding["duplicate_key"]
                    for finding in findings
                }
            )
        )

        flash(
            f"Report imported successfully with "
            f"{len(findings)} finding(s). "
            f"{duplicate_count} duplicate candidate(s) detected."
        )

        return redirect(
            url_for(
                "view_report",
                report_id=report_id,
            )
        )

    return render_template(
        "upload.html"
    )


# =========================================================
# DEMO REPORT
# =========================================================

@app.route(
    "/reports/demo",
    methods=["POST"],
)
@login_required
def load_demo_report():
    """Load the built-in demonstration report."""

    if not DEMO_REPORT.exists():

        flash(
            "The demonstration report could not be found."
        )

        return redirect(
            url_for("reports")
        )

    try:

        with DEMO_REPORT.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):

        flash(
            "The demonstration report could not be read."
        )

        return redirect(
            url_for("reports")
        )

    try:

        findings = parse_report(
            data
        )

        findings = analyze_findings(
            findings
        )

    except ValueError as error:

        flash(
            f"Demo report error: {error}"
        )

        return redirect(
            url_for("reports")
        )

    if not findings:

        flash(
            "The demonstration report contains no findings."
        )

        return redirect(
            url_for("reports")
        )

    db = get_db()

    report_id = save_report(
        db=db,
        user_id=session["user_id"],
        name="VulnTrace Demo Assessment",
        source_format="Built-in Demo",
        findings=findings,
    )

    db.close()

    flash(
        f"Demo report loaded successfully with "
        f"{len(findings)} finding(s)."
    )

    return redirect(
        url_for(
            "view_report",
            report_id=report_id,
        )
    )


# =========================================================
# REPORT DETAILS
# =========================================================

@app.route(
    "/reports/<int:report_id>"
)
@login_required
def view_report(report_id):
    """Display a report and ranked findings."""

    db = get_db()

    report = db.execute(
        """
        SELECT
            id,
            name,
            source_format,
            uploaded_at
        FROM reports
        WHERE id = ?
        AND user_id = ?
        """,
        (
            report_id,
            session["user_id"],
        ),
    ).fetchone()

    if report is None:

        db.close()

        flash(
            "Report not found."
        )

        return redirect(
            url_for("reports")
        )

    findings = db.execute(
        """
        SELECT
            id,
            title,
            severity,
            confidence,
            description,
            evidence,
            asset,
            status,
            evidence_quality,
            risk_score,
            duplicate_of,
            duplicate_count,
            verification_status,
            verified_at,
            created_at
        FROM findings
        WHERE report_id = ?
        ORDER BY
            CASE
                WHEN duplicate_of IS NULL THEN 0
                ELSE 1
            END,
            risk_score DESC,
            id ASC
        """,
        (report_id,),
    ).fetchall()

    unique_count = sum(
        1
        for finding in findings
        if finding["duplicate_of"] is None
    )

    duplicate_count = (
        len(findings)
        - unique_count
    )

    db.close()

    return render_template(
        "report.html",
        report=report,
        findings=findings,
        unique_count=unique_count,
        duplicate_count=duplicate_count,
    )


# =========================================================
# TRIAGE
# =========================================================

@app.route("/triage")
@login_required
def triage():
    """Show the highest-priority unique findings."""

    db = get_db()

    findings = db.execute(
        """
        SELECT
            findings.id,
            findings.title,
            findings.severity,
            findings.confidence,
            findings.risk_score,
            findings.evidence_quality,
            findings.asset,
            findings.duplicate_count,
            findings.status,
            findings.verification_status,
            findings.verified_at,
            reports.name AS report_name
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE reports.user_id = ?
        AND findings.duplicate_of IS NULL
        ORDER BY
            CASE
                WHEN findings.verification_status = 'resolved'
                THEN 1
                ELSE 0
            END,
            findings.risk_score DESC,
            findings.id ASC
        """,
        (session["user_id"],),
    ).fetchall()

    db.close()

    return render_template(
        "triage.html",
        findings=findings,
    )


# =========================================================
# FINDING DETAILS
# =========================================================

@app.route(
    "/findings/<int:finding_id>"
)
@login_required
def view_finding(finding_id):
    """
    Display one security finding with local AI analysis.

    Finding-level AI analysis is cached in SQLite.
    """

    db = get_db()

    finding = db.execute(
        """
        SELECT
            findings.id,
            findings.title,
            findings.severity,
            findings.confidence,
            findings.description,
            findings.evidence,
            findings.asset,
            findings.status,
            findings.evidence_quality,
            findings.risk_score,
            findings.duplicate_key,
            findings.duplicate_of,
            findings.duplicate_count,
            findings.verification_status,
            findings.verification_evidence,
            findings.verified_at,
            reports.id AS report_id,
            reports.name AS report_name
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE findings.id = ?
        AND reports.user_id = ?
        """,
        (
            finding_id,
            session["user_id"],
        ),
    ).fetchone()

    if finding is None:

        db.close()

        flash(
            "Finding not found."
        )

        return redirect(
            url_for("reports")
        )

    finding_data = dict(finding)

    ai_analysis = get_cached_ai_analysis(
        db,
        finding_id,
    )

    ai_error = None

    if ai_analysis is None:

        try:

            ai_analysis = analyze_finding(
                finding_data
            )

            save_ai_analysis(
                db,
                finding_id,
                ai_analysis,
            )

        except Exception as error:

            ai_error = str(error)

    verification_history = db.execute(
        """
        SELECT
            id,
            evidence,
            result,
            ai_assessment,
            created_at
        FROM verifications
        WHERE finding_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (finding_id,),
    ).fetchall()

    db.close()

    return render_template(
        "finding.html",
        finding=finding,
        ai_analysis=ai_analysis,
        ai_error=ai_error,
        verification_history=verification_history,
    )


# =========================================================
# SUBMIT VERIFICATION
# =========================================================

@app.route(
    "/findings/<int:finding_id>/verify",
    methods=["POST"],
)
@login_required
def submit_verification(finding_id):
    """
    Store verification evidence.

    AI does not automatically resolve the vulnerability.
    The initial result is NEEDS_REVIEW.
    """

    evidence = request.form.get(
        "verification_evidence",
        "",
    ).strip()

    if not evidence:

        flash(
            "Please provide verification evidence before submitting."
        )

        return redirect(
            url_for(
                "view_finding",
                finding_id=finding_id,
            )
        )

    db = get_db()

    finding = db.execute(
        """
        SELECT
            findings.id,
            findings.title,
            findings.severity,
            findings.description,
            findings.evidence,
            findings.asset,
            reports.name AS report_name
        FROM findings
        JOIN reports
            ON findings.report_id = reports.id
        WHERE findings.id = ?
        AND reports.user_id = ?
        """,
        (
            finding_id,
            session["user_id"],
        ),
    ).fetchone()

    if finding is None:

        db.close()

        flash(
            "Finding not found."
        )

        return redirect(
            url_for("reports")
        )

    finding_data = dict(finding)

    verification_prompt_data = {
        "finding": finding_data,
        "verification_evidence": evidence,
    }

    ai_assessment = None

    try:

        ai_result = analyze_finding(
            verification_prompt_data
        )

        ai_assessment = json.dumps(
            ai_result,
            ensure_ascii=False,
        )

    except Exception as error:

        ai_assessment = json.dumps(
            {
                "error": str(error),
                "message": (
                    "AI verification assessment was unavailable. "
                    "Manual review is required."
                ),
            },
            ensure_ascii=False,
        )

    db.execute(
        """
        INSERT INTO verifications
        (
            finding_id,
            evidence,
            result,
            ai_assessment
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            finding_id,
            evidence,
            "NEEDS_REVIEW",
            ai_assessment,
        ),
    )

    db.execute(
        """
        UPDATE findings
        SET
            verification_status = 'needs_review',
            verification_evidence = ?,
            verified_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            evidence,
            finding_id,
        ),
    )

    db.commit()

    db.close()

    flash(
        "Verification evidence submitted. "
        "The finding now requires review."
    )

    return redirect(
        url_for(
            "view_finding",
            finding_id=finding_id,
        )
    )


# =========================================================
# RESOLVE VERIFICATION
# =========================================================

@app.route(
    "/findings/<int:finding_id>/verification/<int:verification_id>/resolve",
    methods=["POST"],
)
@login_required
def resolve_verification(
    finding_id,
    verification_id,
):
    """
    Explicitly mark a verification as resolved.

    This is a human-confirmed action.
    """

    db = get_db()

    verification = db.execute(
        """
        SELECT
            verifications.id
        FROM verifications
        JOIN findings
            ON verifications.finding_id = findings.id
        JOIN reports
            ON findings.report_id = reports.id
        WHERE verifications.id = ?
        AND verifications.finding_id = ?
        AND reports.user_id = ?
        """,
        (
            verification_id,
            finding_id,
            session["user_id"],
        ),
    ).fetchone()

    if verification is None:

        db.close()

        flash(
            "Verification record not found."
        )

        return redirect(
            url_for(
                "view_finding",
                finding_id=finding_id,
            )
        )

    db.execute(
        """
        UPDATE verifications
        SET result = 'RESOLVED'
        WHERE id = ?
        """,
        (verification_id,),
    )

    db.execute(
        """
        UPDATE findings
        SET
            verification_status = 'resolved',
            status = 'resolved',
            verified_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (finding_id,),
    )

    db.commit()

    db.close()

    flash(
        "Finding marked as resolved."
    )

    return redirect(
        url_for(
            "view_finding",
            finding_id=finding_id,
        )
    )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

ensure_database_schema()


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)
