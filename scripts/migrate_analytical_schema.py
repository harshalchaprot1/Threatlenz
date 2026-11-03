"""Migration Script: Atomically replaces analytical tables while preserving backup tables."""

import sys
from pathlib import Path

# Ensure project root is in python path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

import sqlalchemy
from src.config import settings
from src.utils import get_logger

logger = get_logger("ThreatLenz.Migration.AnalyticalSchema")

MIGRATION_SQL = """
BEGIN;

-- 1. Guard against accidental repeated execution
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'analytical_confusion_matrix_backup_v1') THEN
        RAISE EXCEPTION 'Safety check failed: analytical_confusion_matrix_backup_v1 already exists. Migration aborted.';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'analytical_port_concentration_backup_v1') THEN
        RAISE EXCEPTION 'Safety check failed: analytical_port_concentration_backup_v1 already exists. Migration aborted.';
    END IF;
END $$;

-- 2. Rename tables
ALTER TABLE analytical_confusion_matrix RENAME TO analytical_confusion_matrix_backup_v1;
ALTER TABLE analytical_port_concentration RENAME TO analytical_port_concentration_backup_v1;

-- 3. Rename sequences
ALTER SEQUENCE analytical_confusion_matrix_id_seq RENAME TO analytical_confusion_matrix_backup_v1_id_seq;
ALTER SEQUENCE analytical_port_concentration_id_seq RENAME TO analytical_port_concentration_backup_v1_id_seq;

-- 4. Rename PK constraints (which renames backing PK unique indexes)
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT analytical_confusion_matrix_pkey TO analytical_confusion_matrix_backup_v1_pkey;

ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT analytical_port_concentration_pkey TO analytical_port_concentration_backup_v1_pkey;

-- 5. Rename secondary constraints on backup tables
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT uq_confusion_cell TO uq_confusion_cell_backup_v1;
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT ck_cm_evaluated_split TO ck_cm_evaluated_split_backup_v1;
ALTER TABLE analytical_confusion_matrix_backup_v1 
    RENAME CONSTRAINT analytical_confusion_matrix_run_id_fkey TO analytical_confusion_matrix_backup_v1_run_id_fkey;

ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT uq_port_concentration TO uq_port_concentration_backup_v1;
ALTER TABLE analytical_port_concentration_backup_v1 
    RENAME CONSTRAINT analytical_port_concentration_run_id_fkey TO analytical_port_concentration_backup_v1_run_id_fkey;

-- 6. Rename secondary indexes on backup tables
ALTER INDEX ix_cm_labels RENAME TO ix_cm_labels_backup_v1;
ALTER INDEX ix_cm_run_split RENAME TO ix_cm_run_split_backup_v1;
ALTER INDEX ix_port_run_cat RENAME TO ix_port_run_cat_backup_v1;
ALTER INDEX ix_port_num RENAME TO ix_port_num_backup_v1;

-- 7. Create target analytical_confusion_matrix
CREATE TABLE analytical_confusion_matrix (
    id                    BIGSERIAL PRIMARY KEY,
    source_report_hash    VARCHAR(64)   NOT NULL,
    report_timestamp      VARCHAR(32)   NOT NULL,
    pipeline_name         VARCHAR(128)  NOT NULL,
    model_artifact        VARCHAR(255)  NOT NULL,
    run_id                VARCHAR(64)   REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    evaluated_split       VARCHAR(32)   NOT NULL,
    true_label            VARCHAR(64)   NOT NULL,
    predicted_label       VARCHAR(64)   NOT NULL,
    true_label_idx        INTEGER       NOT NULL,
    predicted_label_idx   INTEGER       NOT NULL,
    raw_count             BIGINT        NOT NULL,
    true_class_support    BIGINT        NOT NULL,
    normalized_ratio      NUMERIC(8, 4) NOT NULL,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT ck_cm_evaluated_split CHECK (evaluated_split IN ('validation', 'test')),
    CONSTRAINT uq_confusion_cell UNIQUE (
        source_report_hash,
        evaluated_split,
        true_label,
        predicted_label
    )
);

CREATE INDEX ix_cm_hash_split ON analytical_confusion_matrix (source_report_hash, evaluated_split);
CREATE INDEX ix_cm_run_id ON analytical_confusion_matrix (run_id);
CREATE INDEX ix_cm_labels ON analytical_confusion_matrix (true_label, predicted_label);

-- 8. Create target analytical_port_concentration
CREATE TABLE analytical_port_concentration (
    id                         BIGSERIAL PRIMARY KEY,
    source_report_hash         VARCHAR(64)   NOT NULL,
    report_timestamp           VARCHAR(32)   NOT NULL,
    report_name                VARCHAR(128)  NOT NULL,
    dataset_path               VARCHAR(255)  NOT NULL,
    run_id                     VARCHAR(64)   REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    threat_category            VARCHAR(64)   NOT NULL,
    destination_port           INTEGER       NOT NULL,
    service_name               VARCHAR(128),
    criticality_weight         INTEGER       NOT NULL DEFAULT 50,
    flow_count                 BIGINT        NOT NULL,
    total_class_flows          BIGINT        NOT NULL,
    percentage_within_class    NUMERIC(6, 2) NOT NULL,
    has_extreme_concentration  BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_port_concentration UNIQUE (
        source_report_hash,
        threat_category,
        destination_port
    )
);

CREATE INDEX ix_port_hash_cat ON analytical_port_concentration (source_report_hash, threat_category);
CREATE INDEX ix_port_run_id ON analytical_port_concentration (run_id);
CREATE INDEX ix_port_num ON analytical_port_concentration (destination_port);

COMMIT;
"""


def run_migration() -> int:
    engine = sqlalchemy.create_engine(settings.effective_database_url, isolation_level="AUTOCOMMIT")
    logger.info("Executing safe atomic schema migration for Phase 2 analytical tables...")
    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text(MIGRATION_SQL))
        logger.info("Schema migration completed successfully.")
        print("SUCCESS: Analytical tables migrated to cryptographic schema. Backup tables preserved.")
        return 0
    except Exception as exc:
        logger.error("Migration failed: %s", exc)
        print(f"ERROR: Migration failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_migration())

