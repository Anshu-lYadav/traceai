"""Explainable first-pass anomaly flags for structured CSV and JSON logs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest


MODEL_VERSION = "trace-rules-iforest-1"
TIMESTAMP_HINTS = ("timestamp", "datetime", "date_time", "event_time", "date", "time")
USER_HINTS = ("user", "username", "account", "actor", "owner", "employee", "principal")
ACTIVITY_HINTS = ("event", "activity", "action", "operation", "event_type", "activity_type")


def _find_column(columns: list[str], hints: tuple[str, ...]) -> str | None:
    normalized = {column: str(column).strip().lower().replace(" ", "_") for column in columns}
    for hint in hints:
        for original, value in normalized.items():
            if value == hint or value.endswith("_" + hint) or value.startswith(hint + "_"):
                return original
    return None


def _csv_source_rows(path: Path, expected: int) -> list[int]:
    source_rows: list[int] = []
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source)
        try:
            next(reader)
        except StopIteration:
            return source_rows
        for position in range(expected):
            for row in reader:
                if row:
                    source_rows.append(reader.line_num)
                    break
            else:
                source_rows.append(position + 2)
    return source_rows


def _load_records(item: dict[str, Any]) -> pd.DataFrame:
    path = Path(item.get("original_path", ""))
    suffix = path.suffix.lower()
    if suffix == ".csv":
        frame = pd.read_csv(path, low_memory=False)
        frame.attrs["source_rows"] = _csv_source_rows(path, len(frame))
    elif suffix == ".json":
        with path.open("r", encoding="utf-8-sig") as source:
            payload = json.load(source)
        if isinstance(payload, list):
            frame = pd.json_normalize(payload)
        elif isinstance(payload, dict):
            # A single record is one row; column-oriented JSON is accepted by pandas.
            frame = pd.json_normalize(payload)
        else:
            raise ValueError("JSON must contain an object or a list of objects.")
    else:
        raise ValueError("Anomaly analysis currently supports CSV and JSON evidence only.")
    if frame.empty:
        raise ValueError("The file contains no records.")
    if len(frame.columns) == 0:
        raise ValueError("No columns were found in the structured file.")
    return frame


def analyze_structured_evidence(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return flagged original rows and per-file analysis summaries."""
    flagged: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []

    for item in items:
        if item.get("file_type", "").lower() not in {"csv", "json"}:
            continue
        try:
            frame = _load_records(item)
            row_count = len(frame)
            timestamp_col = _find_column(list(frame.columns), TIMESTAMP_HINTS)
            user_col = _find_column(list(frame.columns), USER_HINTS)
            activity_col = _find_column(list(frame.columns), ACTIVITY_HINTS)

            timestamps = (
                pd.to_datetime(frame[timestamp_col], errors="coerce", utc=True, format="mixed")
                if timestamp_col else pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")
            )
            explicit_timezone = (
                frame[timestamp_col].fillna("").astype(str).str.contains(
                    r"(?:Z|[+-]\d{2}:?\d{2})$", case=False, regex=True
                )
                if timestamp_col else pd.Series(False, index=frame.index)
            )
            users = (
                frame[user_col].fillna("unknown").astype(str).str.strip().str.lower()
                if user_col else pd.Series("unknown", index=frame.index)
            )
            activities = (
                frame[activity_col].fillna("unknown").astype(str).str.strip().str.lower()
                if activity_col else pd.Series("unknown", index=frame.index)
            )

            reasons: list[list[str]] = [[] for _ in range(row_count)]
            parsed_hours = timestamps.dt.hour
            for pos, hour in enumerate(parsed_hours.tolist()):
                if explicit_timezone.iloc[pos] and pd.notna(hour) and (hour < 6 or hour >= 22):
                    reasons[pos].append(f"Timezone-explicit timestamp is outside 06:00–21:59 UTC ({int(hour):02d}:00 UTC).")

            if activity_col and row_count >= 10:
                frequencies = activities.value_counts(dropna=False)
                for pos, activity in enumerate(activities.tolist()):
                    if activity != "unknown" and frequencies.get(activity, row_count) <= max(2, int(row_count * 0.01)):
                        reasons[pos].append("Activity type is rare within this file.")

            burst_flags = pd.Series(False, index=frame.index)
            if timestamp_col and user_col:
                valid = timestamps.notna() & explicit_timezone
                if valid.any():
                    hours = timestamps.dt.floor("h")
                    counts = users[valid].groupby([users[valid], hours[valid]]).transform("size")
                    burst_flags.loc[valid] = counts >= 5
                    for pos, is_burst in enumerate(burst_flags.tolist()):
                        if is_burst:
                            reasons[pos].append(
                                "At least five timezone-explicit records for this account share the same UTC hour."
                            )

            if row_count >= 20:
                hour_feature = parsed_hours.fillna(-1).astype(float)
                day_feature = timestamps.dt.dayofweek.fillna(-1).astype(float)
                activity_frequency = activities.map(activities.value_counts()).fillna(0).astype(float)
                user_frequency = users.map(users.value_counts()).fillna(0).astype(float)
                text_length = frame.fillna("").astype(str).apply(
                    lambda column: column.str.len()
                ).sum(axis=1).astype(float)
                features = pd.DataFrame({
                    "hour": hour_feature,
                    "day_of_week": day_feature,
                    "activity_frequency": activity_frequency,
                    "user_frequency": user_frequency,
                    "record_text_length": text_length,
                    "burst": burst_flags.astype(float),
                }).replace([float("inf"), float("-inf")], 0).fillna(0)
                detector = IsolationForest(
                    n_estimators=100,
                    contamination="auto",
                    random_state=42,
                )
                predictions = detector.fit_predict(features)
                anomaly_scores = -detector.decision_function(features)
                for pos, prediction in enumerate(predictions):
                    if prediction == -1:
                        reasons[pos].append(
                            f"Isolation Forest ranked this record as unusual (score {anomaly_scores[pos]:.3f}; higher means more unusual in this file)."
                        )

            flagged_positions = [pos for pos, row_reasons in enumerate(reasons) if row_reasons]
            source_rows = frame.attrs.get("source_rows", [])
            for pos in flagged_positions:
                original = frame.iloc[pos].where(pd.notna(frame.iloc[pos]), None).to_dict()
                if item["file_type"].lower() == "csv":
                    row_number = source_rows[pos] if pos < len(source_rows) else pos + 2
                else:
                    row_number = pos + 1
                flagged.append({
                    "evidence_id": item["evidence_id"],
                    "filename": item["filename"],
                    "row_number": row_number,
                    "reasons": reasons[pos],
                    "original_record": {str(key): value for key, value in original.items()},
                })

            summaries.append({
                "evidence_id": item["evidence_id"],
                "filename": item["filename"],
                "records_analyzed": row_count,
                "records_flagged": len(flagged_positions),
                "timestamp_column": str(timestamp_col) if timestamp_col else "Not detected",
                "account_column": str(user_col) if user_col else "Not detected",
                "activity_column": str(activity_col) if activity_col else "Not detected",
                "status": "Analysis completed",
            })
        except Exception as exc:
            summaries.append({
                "evidence_id": item["evidence_id"],
                "filename": item["filename"],
                "records_analyzed": 0,
                "records_flagged": 0,
                "timestamp_column": "Not detected",
                "account_column": "Not detected",
                "activity_column": "Not detected",
                "status": f"Could not analyze: {exc}",
            })

    return flagged, summaries

