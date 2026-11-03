"""Exhaustive Verification Script for Phase 2 Analytical Tables.

Validates:
1. All 5 core tables match their full baseline SHA-256 cryptographic digests.
2. All 392 confusion matrix cells match clean_per_class_rf_evaluation_report.json exactly.
3. All 27 destination port records match spark_analytics_report.json exactly.
4. run_id is verified as NULL (standalone provenance).
5. Source report content hashes match on-disk files.
"""

import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

# Ensure project root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

import sqlalchemy
from src.config import settings

# Full 64-character SHA-256 baseline hashes of core tables
CORE_TABLE_BASELINES = {
    "pipeline_runs": "4abdf967dbf3caa9f52951c04671790bdb3af9733c868db96d1945e105ca7987",
    "threat_profiles": "6e214117fe317cc32aa3300bb8f23d33e34cb724a8e09575016fe9c73cc76e62",
    "mitre_mappings": "0e212907e29747c391069f7f39b568086e8cdbb4de3baa44225780cceabda209",
    "risk_assessments": "f4af59a29d9c283ee87c27fdfd3aae983bbce30b46b520d3107614a19d925275",
    "advisories": "99980d10341dfe948d3c54fc6c4d414a4fe37ceb15aa455cb03bcf00d54e2eef",
}


def compute_file_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_all() -> int:
    engine = sqlalchemy.create_engine(settings.effective_database_url)

    rf_report_path = project_root / "reports" / "clean_per_class_rf_evaluation_report.json"
    spark_report_path = project_root / "reports" / "spark_analytics_report.json"

    expected_rf_hash = compute_file_sha256(rf_report_path)
    expected_spark_hash = compute_file_sha256(spark_report_path)

    with open(rf_report_path, "r", encoding="utf-8") as f:
        rf_data = json.load(f)
    with open(spark_report_path, "r", encoding="utf-8") as f:
        spark_data = json.load(f)

    with engine.connect() as conn:
        print("=== 1. VERIFYING CORE TABLE CONTENT INVARIANCE ===")
        for tbl, expected_hash in CORE_TABLE_BASELINES.items():
            rows = conn.execute(sqlalchemy.text(f"SELECT * FROM {tbl} ORDER BY 1;")).fetchall()
            serialized = json.dumps([list(map(str, r)) for r in rows], sort_keys=True)
            actual_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            print(f"Table {tbl} ({len(rows)} rows): hash={actual_hash[:16]}... ", end="")
            assert actual_hash == expected_hash, f"FAILED: Core table {tbl} was modified! {actual_hash} != {expected_hash}"
            print("[MATCH]")

        print("\n=== 2. VERIFYING BACKUP TABLES EXIST AND CONTAIN ORIGINAL RECORDS ===")
        backup_cm = conn.execute(sqlalchemy.text(
            "SELECT COUNT(*) FROM analytical_confusion_matrix_backup_v1;"
        )).scalar()
        assert backup_cm == 392, (
            f"Expected 392 rows in analytical_confusion_matrix_backup_v1, found {backup_cm}"
        )
        print(f"analytical_confusion_matrix_backup_v1: {backup_cm} rows [OK]")

        backup_port = conn.execute(sqlalchemy.text(
            "SELECT COUNT(*) FROM analytical_port_concentration_backup_v1;"
        )).scalar()
        assert backup_port == 27, (
            f"Expected 27 rows in analytical_port_concentration_backup_v1, found {backup_port}"
        )
        print(f"analytical_port_concentration_backup_v1: {backup_port} rows [OK]")

        print("\n=== 3. VERIFYING CONFUSION MATRIX (392 CELLS) ===")
        cm_rows = conn.execute(sqlalchemy.text(
            "SELECT source_report_hash, report_timestamp, pipeline_name, model_artifact, run_id, "
            "evaluated_split, true_label, predicted_label, true_label_idx, predicted_label_idx, "
            "raw_count, true_class_support, normalized_ratio "
            "FROM analytical_confusion_matrix ORDER BY evaluated_split, true_label_idx, predicted_label_idx;"
        )).fetchall()
        assert len(cm_rows) == 392, f"Expected 392 confusion matrix cells, found {len(cm_rows)}"

        # Build lookup: (split, true_idx, pred_idx) -> row
        cm_dict = {(r[5], r[8], r[9]): r for r in cm_rows}

        cells_validated = 0
        for split in ["validation", "test"]:
            split_metrics = rf_data[f"{split}_metrics"]["confusion_matrix"]
            class_labels = split_metrics["class_labels"]
            raw_matrix = split_metrics["raw_matrix"]
            norm_matrix = split_metrics["normalized_matrix"]

            for i, true_lbl in enumerate(class_labels):
                expected_support = sum(raw_matrix[i])
                for j, pred_lbl in enumerate(class_labels):
                    row = cm_dict[(split, i, j)]
                    assert row[0] == expected_rf_hash, f"Hash mismatch in CM cell {split}[{i},{j}]: {row[0]!r} != {expected_rf_hash!r}"
                    assert row[1] == rf_data["timestamp"], f"Timestamp mismatch in CM cell {split}[{i},{j}]: {row[1]!r} != {rf_data['timestamp']!r}"
                    assert row[4] is None, f"Expected run_id=NULL in CM cell {split}[{i},{j}], got {row[4]!r}"
                    assert row[6] == true_lbl, f"True label mismatch at [{i},{j}]: {row[6]!r} != {true_lbl!r}"
                    assert row[7] == pred_lbl, f"Predicted label mismatch at [{i},{j}]: {row[7]!r} != {pred_lbl!r}"
                    assert int(row[10]) == int(raw_matrix[i][j]), (
                        f"Raw count mismatch at {split}[{i},{j}]: {row[10]} != {raw_matrix[i][j]}"
                    )
                    assert int(row[11]) == int(expected_support), (
                        f"Support mismatch at {split}[{i}]: {row[11]} != {expected_support}"
                    )
                    # normalized_ratio stored as NUMERIC(8,4) — compare as Decimal rounded to 4dp
                    expected_ratio = Decimal(str(round(float(norm_matrix[i][j]), 4)))
                    assert row[12] == expected_ratio, (
                        f"Ratio mismatch at {split}[{i},{j}]: {row[12]} != {expected_ratio}"
                    )
                    cells_validated += 1

        print(f"Validated all {cells_validated} confusion matrix cells against JSON with 100% precision.")

        print("\n=== 4. VERIFYING PORT CONCENTRATION (27 RECORDS) ===")
        port_rows = conn.execute(sqlalchemy.text(
            "SELECT source_report_hash, report_timestamp, report_name, dataset_path, run_id, "
            "threat_category, destination_port, service_name, criticality_weight, "
            "flow_count, total_class_flows, percentage_within_class, has_extreme_concentration "
            "FROM analytical_port_concentration ORDER BY threat_category, destination_port;"
        )).fetchall()
        assert len(port_rows) == 27, f"Expected 27 port records, found {len(port_rows)}"

        port_dict = {(r[5], r[6]): r for r in port_rows}
        ports_validated = 0
        for cat_name, cat_obj in spark_data["destination_port_analysis"].items():
            if not isinstance(cat_obj, dict):
                continue
            total_flows = int(cat_obj["total_flows"])
            has_extreme = bool(cat_obj["has_extreme_port_concentration"])
            for p in cat_obj.get("top_ports", []):
                p_num = int(p["port"])
                row = port_dict[(cat_name, p_num)]
                assert row[0] == expected_spark_hash, (
                    f"Hash mismatch in Port {cat_name}:{p_num}: {row[0]!r} != {expected_spark_hash!r}"
                )
                assert row[1] == spark_data["timestamp"], (
                    f"Timestamp mismatch in Port {cat_name}:{p_num}: {row[1]!r} != {spark_data['timestamp']!r}"
                )
                assert row[4] is None, f"Expected run_id=NULL in Port {cat_name}:{p_num}, got {row[4]!r}"
                assert int(row[9]) == int(p["flow_count"]), (
                    f"Flow count mismatch at {cat_name}:{p_num}: {row[9]} != {p['flow_count']}"
                )
                assert int(row[10]) == total_flows, (
                    f"Total flows mismatch at {cat_name}:{p_num}: {row[10]} != {total_flows}"
                )
                # percentage_within_class stored as NUMERIC(6,2) — compare rounded to 2dp
                expected_pct = Decimal(str(round(float(p["percentage_within_class"]), 2)))
                assert row[11] == expected_pct, (
                    f"Percentage mismatch at {cat_name}:{p_num}: {row[11]} != {expected_pct}"
                )
                assert bool(row[12]) == has_extreme, (
                    f"Extreme concentration flag mismatch at {cat_name}:{p_num}: {row[12]} != {has_extreme}"
                )
                ports_validated += 1

        print(f"Validated all {ports_validated} destination-port records against JSON with 100% precision.")

    print("\n============================================================")
    print("SUCCESS: ALL 392 CONFUSION CELLS, 27 PORT RECORDS, 2 BACKUP")
    print("TABLES, AND 5 CORE TABLES MATCH EXPECTED BASELINES WITH")
    print("100% MATHEMATICAL PRECISION.")
    print("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(verify_all())
