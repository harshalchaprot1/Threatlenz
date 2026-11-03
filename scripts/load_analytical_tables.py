"""CLI script to ingest Phase 2 PostgreSQL analytical tables."""

import argparse
import sys
from pathlib import Path

# Ensure project root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from src.database import (
    get_db_engine,
    get_db_session,
    ingest_analytical_tables,
)
from src.utils import get_logger

logger = get_logger("ThreatLenz.CLI.AnalyticalLoader")


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest Phase 2 analytical tables with cryptographic provenance.")
    parser.add_argument("--reports-dir", type=str, default=None, help="Directory containing JSON reports.")
    parser.add_argument("--standalone", action="store_true", default=True, help="Ingest standalone without associating pipeline run (run_id=NULL). Default.")
    parser.add_argument("--link-run-id", type=str, default=None, help="Explicit trustworthy pipeline run_id to link. Rejected if model provenance diverges.")
    args = parser.parse_args()

    engine = get_db_engine()

    with get_db_session(engine) as session:
        try:
            results = ingest_analytical_tables(
                reports_dir=args.reports_dir,
                link_run_id=args.link_run_id,
                session=session,
            )
            session.commit()
            logger.info("Ingestion complete: %s", results)
            print(
                f"SUCCESS: Ingested {results['confusion_matrix_rows']} confusion cells (hash: {results['rf_report_hash'][:12]}...), "
                f"{results['port_concentration_rows']} port concentration records (hash: {results['spark_report_hash'][:12]}...). "
                f"run_id={results['run_id']}"
            )
            return 0
        except Exception as e:
            session.rollback()
            logger.error("Ingestion failed: %s", e)
            print(f"ERROR: {e}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
