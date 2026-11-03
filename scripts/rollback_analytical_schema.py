"""Rollback Script: Safely restores original analytical tables and constraints from backup."""

import sys
from pathlib import Path

# Ensure project root is in python path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

import sqlalchemy
from src.config import settings
from src.utils import get_logger

logger = get_logger("ThreatLenz.Rollback.AnalyticalSchema")

ROLLBACK_SQL = """
BEGIN;

-- 1. Guard check: Ensure backup tables actually exist before attempting rollback
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'analytical_confusion_matrix_backup_v1') THEN
        RAISE EXCEPTION 'Rollback safety check failed: analytical_confusion_matrix_backup_v1 does not exist.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'analytical_port_concentration_backup_v1') THEN
        RAISE EXCEPTION 'Rollback safety check failed: analytical_port_concentration_backup_v1 does not exist.';
    END IF;
END $$;

-- 2. Drop replacement analytical tables (without CASCADE)
DROP TABLE IF EXISTS analytical_confusion_matrix;
DROP TABLE IF EXISTS analytical_port_concentration;

-- 3. Restore secondary index names on backup tables
ALTER INDEX ix_cm_labels_backup_v1 RENAME TO ix_cm_labels;
ALTER INDEX ix_cm_run_split_backup_v1 RENAME TO ix_cm_run_split;
ALTER INDEX ix_port_run_cat_backup_v1 RENAME TO ix_port_run_cat;
ALTER INDEX ix_port_num_backup_v1 RENAME TO ix_port_num;

-- 4. Restore secondary constraints on backup tables
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT uq_confusion_cell_backup_v1 TO uq_confusion_cell;
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT ck_cm_evaluated_split_backup_v1 TO ck_cm_evaluated_split;
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT analytical_confusion_matrix_backup_v1_run_id_fkey TO analytical_confusion_matrix_run_id_fkey;

ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT uq_port_concentration_backup_v1 TO uq_port_concentration;
ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT analytical_port_concentration_backup_v1_run_id_fkey TO analytical_port_concentration_run_id_fkey;

-- 5. Restore PK constraints on backup tables (restores canonical PK index names)
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT analytical_confusion_matrix_backup_v1_pkey TO analytical_confusion_matrix_pkey;

ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT analytical_port_concentration_backup_v1_pkey TO analytical_port_concentration_pkey;

-- 6. Restore sequence names
ALTER SEQUENCE analytical_confusion_matrix_backup_v1_id_seq RENAME TO analytical_confusion_matrix_id_seq;
ALTER SEQUENCE analytical_port_concentration_backup_v1_id_seq RENAME TO analytical_port_concentration_id_seq;

-- 7. Restore original table names
ALTER TABLE analytical_confusion_matrix_backup_v1 RENAME TO analytical_confusion_matrix;
ALTER TABLE analytical_port_concentration_backup_v1 RENAME TO analytical_port_concentration;

COMMIT;
"""


def run_rollback() -> int:
    engine = sqlalchemy.create_engine(settings.effective_database_url, isolation_level="AUTOCOMMIT")
    logger.info("Executing safe atomic rollback for Phase 2 analytical tables...")
    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text(ROLLBACK_SQL))
        logger.info("Rollback completed successfully.")
        print("SUCCESS: Analytical tables and constraints fully restored from backup_v1.")
        return 0
    except Exception as exc:
        logger.error("Rollback failed: %s", exc)
        print(f"ERROR: Rollback failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_rollback())

