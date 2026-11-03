"""Export all 63 Random Forest feature importances to a verified JSON artifact.

Loads the saved PySpark PipelineModel stages directly via PyArrow and JSON metadata
without requiring a PySpark JVM or Windows Hadoop native binaries.
Reproduces Spark's weighted feature-importance algorithm across all 30 trees:
  1. Reads VectorAssembler stage metadata to obtain true training feature index order (63 features).
  2. Reads RandomForestClassificationModel tree data Parquet via PyArrow.
  3. Weights each split gain by sum(impurityStats) (the class-weighted node observation count).
  4. Normalizes split gains per-tree, then averages across all trees.
  5. Cross-validates all values against stored top-10 report (delta < 1e-6).
  6. Writes reports/all_feature_importances.json.

Usage:
    python scripts/export_all_feature_importances.py
"""

from __future__ import annotations

import collections
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List

import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_STAGES_DIR = PROJECT_ROOT / "models" / "clean_per_class_rf" / "model" / "stages"
REPORT_PATH = PROJECT_ROOT / "reports" / "clean_per_class_rf_evaluation_report.json"
OUTPUT_PATH = PROJECT_ROOT / "reports" / "all_feature_importances.json"

EXPECTED_FEATURE_COUNT = 63
TOP10_TOLERANCE = 1e-6


def _abort(msg: str) -> None:
    print(f"\n[ABORT] {msg}", file=sys.stderr)
    sys.exit(1)


def _load_vector_assembler_ordering() -> List[str]:
    """Finds VectorAssembler stage metadata and extracts exact inputCols in training order."""
    va_dirs = list(MODEL_STAGES_DIR.glob("*_VectorAssembler_*"))
    if not va_dirs:
        _abort(f"VectorAssembler stage not found in {MODEL_STAGES_DIR}")
    
    meta_path = va_dirs[0] / "metadata" / "part-00000"
    if not meta_path.exists():
        _abort(f"VectorAssembler metadata missing at {meta_path}")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    input_cols: List[str] = meta.get("paramMap", {}).get("inputCols", [])
    if len(input_cols) != EXPECTED_FEATURE_COUNT:
        _abort(
            f"VectorAssembler inputCols has {len(input_cols)} entries; "
            f"expected exactly {EXPECTED_FEATURE_COUNT}."
        )

    print(f"[OK] VectorAssembler inputCols verified: {len(input_cols)} features in exact model order.")
    return input_cols


def _clean_feature_name(raw_name: str) -> str:
    """Maps VectorAssembler column name to canonical feature name."""
    if raw_name == "protocol_idx":
        return "protocol"
    return raw_name.replace("__imp", "")


def _load_stored_top10() -> Dict[str, float]:
    """Loads stored top-10 importances for cross-validation."""
    if not REPORT_PATH.exists():
        _abort(f"Evaluation report not found at {REPORT_PATH}")

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    top10: Dict[str, float] = report.get("top_10_feature_importances", {})
    if len(top10) != 10:
        _abort(f"Stored top_10_feature_importances has {len(top10)} entries; expected 10.")

    print(f"[OK] Stored top-10 importances loaded for cross-validation.")
    return top10


def _extract_rf_importances(va_input_cols: List[str]) -> List[float]:
    """Computes exact Random Forest feature importances from Parquet tree data."""
    rf_dirs = list(MODEL_STAGES_DIR.glob("*_RandomForestClassifier_*"))
    if not rf_dirs:
        _abort(f"RandomForestClassifier stage not found in {MODEL_STAGES_DIR}")
    
    rf_stage = rf_dirs[0]
    meta_path = rf_stage / "metadata" / "part-00000"
    if not meta_path.exists():
        _abort(f"RandomForest metadata missing at {meta_path}")

    with open(meta_path, "r", encoding="utf-8") as f:
        rf_meta = json.load(f)
    num_trees = rf_meta.get("numTrees", 30)

    data_files = list((rf_stage / "data").glob("*.parquet"))
    if not data_files:
        _abort(f"RandomForest data parquet missing in {rf_stage / 'data'}")

    table = pq.read_table(data_files[0])
    rows = table.to_pylist()

    per_tree: Dict[int, Dict[int, float]] = collections.defaultdict(lambda: collections.defaultdict(float))
    per_tree_total: Dict[int, float] = collections.defaultdict(float)

    for row in rows:
        tid = row["treeID"]
        nd = row["nodeData"]
        gain = nd.get("gain", 0.0)
        split = nd.get("split")
        if split is None or gain <= 0:
            continue
        
        # In weighted Random Forest, impurityStats contains weighted observation counts per class
        ist = nd.get("impurityStats") or []
        weighted_count = sum(ist)
        feat_idx = split.get("featureIndex", -1)
        if feat_idx < 0 or feat_idx >= EXPECTED_FEATURE_COUNT:
            continue
        
        wg = gain * weighted_count
        per_tree[tid][feat_idx] += wg
        per_tree_total[tid] += wg

    if len(per_tree) != num_trees:
        _abort(f"Found splits for {len(per_tree)} trees, expected {num_trees}.")

    feature_avg: Dict[int, float] = collections.defaultdict(float)
    for tid, feat_dict in per_tree.items():
        tree_total = per_tree_total[tid]
        if tree_total <= 0:
            continue
        for feat_idx, wg in feat_dict.items():
            feature_avg[feat_idx] += (wg / tree_total) / num_trees

    imp_list = [feature_avg.get(i, 0.0) for i in range(EXPECTED_FEATURE_COUNT)]
    return imp_list


def _validate_and_format(
    imp_list: List[float],
    va_input_cols: List[str],
    stored_top10: Dict[str, float],
) -> List[Dict[str, Any]]:
    """Validates count, finite/non-negative properties, sum to 1.0, and top-10 exact match."""
    if len(imp_list) != EXPECTED_FEATURE_COUNT:
        _abort(f"Calculated {len(imp_list)} importances; expected {EXPECTED_FEATURE_COUNT}.")

    for idx, val in enumerate(imp_list):
        if not math.isfinite(val) or val < 0.0:
            _abort(f"Invalid importance value at index {idx} ({va_input_cols[idx]}): {val}")

    total = sum(imp_list)
    if abs(total - 1.0) > 1e-6:
        _abort(f"Sum of feature importances is {total:.10f}, expected 1.0 within 1e-6.")
    print(f"[OK] Normalization verified: Sum = {total:.10f}")

    print("\n[INFO] Cross-validating against stored top-10 report (tolerance < 1e-6)...")
    for raw_name, stored_val in sorted(stored_top10.items(), key=lambda x: -x[1]):
        clean = _clean_feature_name(raw_name)
        if raw_name in va_input_cols:
            idx = va_input_cols.index(raw_name)
        elif clean == "protocol":
            idx = va_input_cols.index("protocol_idx")
        else:
            _abort(f"Feature '{raw_name}' from top-10 report not found in VectorAssembler cols.")
        
        computed_val = imp_list[idx]
        delta = abs(computed_val - stored_val)
        if delta > TOP10_TOLERANCE:
            _abort(
                f"Mismatch on feature '{clean}' (index {idx}): "
                f"stored={stored_val:.8f}, computed={computed_val:.8f}, delta={delta:.8e}"
            )
        print(f"  [PASS] {clean:<24} (idx {idx:2d}) stored={stored_val:.6f} computed={computed_val:.6f} delta={delta:.8e}")

    print("\n[OK] All 10 top-10 features match stored report exactly.")

    items: List[Dict[str, Any]] = []
    for idx, col in enumerate(va_input_cols):
        clean_name = _clean_feature_name(col)
        items.append({
            "feature_name": col,
            "clean_feature_name": clean_name,
            "training_index": idx,
            "importance": round(imp_list[idx], 8),
            "rank": 0,
        })

    items.sort(key=lambda x: x["importance"], reverse=True)
    for rank, item in enumerate(items, start=1):
        item["rank"] = rank

    return items


def _write_artifact(items: List[Dict[str, Any]]) -> None:
    """Writes verified results to reports/all_feature_importances.json."""
    payload = {
        "artifact_name": "all_feature_importances",
        "model_artifact": "models/clean_per_class_rf/model",
        "feature_count": EXPECTED_FEATURE_COUNT,
        "feature_ordering": "Sorted descending by importance (rank 1 = highest)",
        "importance_method": (
            "Spark RandomForestClassificationModel.featureImportances — "
            "weighted Gini impurity reduction per split, normalized per-tree, "
            "averaged across 30 trees to sum to 1.0."
        ),
        "governance_notice": (
            "Extracted directly from the clean Random Forest evaluation benchmark artifact. "
            "Model remains quarantined under governance policy. Does not imply operational causation."
        ),
        "all_feature_importances": items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[SUCCESS] Artifact generated at: {OUTPUT_PATH}")
    print(f"          Features: {len(items)}")
    print(f"          Top: {items[0]['clean_feature_name']} ({items[0]['importance']:.8f})")
    print(f"          Bottom: {items[-1]['clean_feature_name']} ({items[-1]['importance']:.8f})")


def main() -> None:
    print("=" * 70)
    print("ThreatLenz — Exact 63 Feature-Importance Exporter (PyArrow/Parquet)")
    print("=" * 70)
    va_input_cols = _load_vector_assembler_ordering()
    stored_top10 = _load_stored_top10()
    imp_list = _extract_rf_importances(va_input_cols)
    items = _validate_and_format(imp_list, va_input_cols, stored_top10)
    _write_artifact(items)


if __name__ == "__main__":
    main()
