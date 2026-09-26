import json
import sqlite3

from services.ai_analyzer import analyze_finding


DATABASE = "database/vulntrace.db"


def main():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    findings = db.execute(
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
        ORDER BY findings.id
        """
    ).fetchall()

    total = len(findings)

    print("=" * 60)
    print("VulnTrace AI - Pre-cache Local AI Analyses")
    print("=" * 60)
    print(f"Total findings: {total}")
    print()

    cached = 0
    generated = 0
    failed = 0

    for index, finding in enumerate(findings, start=1):
        finding_id = finding["id"]

        existing = db.execute(
            """
            SELECT id
            FROM analyses
            WHERE finding_id = ?
            AND analysis_type = 'finding_ai'
            AND source = 'ollama'
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (finding_id,),
        ).fetchone()

        print(
            f"[{index}/{total}] "
            f"Finding #{finding_id}: "
            f"{finding['title']}"
        )

        if existing is not None:
            print("    -> Already cached. Skipping.")
            cached += 1
            continue

        finding_data = dict(finding)

        try:
            print("    -> Running local Qwen analysis...")

            ai_analysis = analyze_finding(
                finding_data
            )

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

            generated += 1

            print("    -> Cached successfully.")

        except Exception as error:
            failed += 1

            print(
                f"    -> FAILED: {error}"
            )

        print()

    db.close()

    print("=" * 60)
    print("PRE-CACHE COMPLETE")
    print("=" * 60)
    print(f"Already cached : {cached}")
    print(f"Generated      : {generated}")
    print(f"Failed         : {failed}")
    print(f"Total findings : {total}")
    print("=" * 60)


if __name__ == "__main__":
    main()
