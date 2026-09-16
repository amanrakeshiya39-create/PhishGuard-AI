"""
PhishGuard AI - Database Access and Aggregation Service
Provides asynchronous CRUD and analytical aggregation for URL scans.
Seamlessly falls back to an in-memory buffer if MongoDB is unavailable.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from bson import ObjectId

from app.database import db_manager, IN_MEMORY_SCANS
from app.utils.constants import LABEL_PHISHING, LABEL_SUSPICIOUS, LABEL_LOW_RISK


def _format_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures Mongo document has string 'id' and clean serializable fields."""
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


async def save_scan_record(record: Dict[str, Any]) -> str:
    """Inserts a new scan report into MongoDB or memory buffer."""
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    record["scanned_at"] = now_iso

    doc = dict(record)
    doc["created_at"] = now_dt
    doc["scanned_at"] = now_iso

    if db_manager.is_connected and db_manager.db is not None:
        try:
            result = await db_manager.db.scans.insert_one(doc)
            return str(result.inserted_id)
        except Exception:
            # Fall back to in-memory on error
            pass

    scan_id = str(uuid.uuid4())
    doc["_id"] = scan_id
    doc["id"] = scan_id
    IN_MEMORY_SCANS.insert(0, doc)
    return scan_id


async def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan by its unique ID."""
    if db_manager.is_connected and db_manager.db is not None:
        try:
            query = {"_id": ObjectId(scan_id)} if ObjectId.is_valid(scan_id) else {"_id": scan_id}
            doc = await db_manager.db.scans.find_one(query)
            if doc:
                return _format_doc(doc)
        except Exception:
            pass

    for s in IN_MEMORY_SCANS:
        if s.get("id") == scan_id or str(s.get("_id")) == scan_id:
            return _format_doc(s)
    return None


async def get_scan_history(
    limit: int = 20,
    skip: int = 0,
    classification: Optional[str] = None,
    search: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieves paginated scan history with optional filtering."""
    if db_manager.is_connected and db_manager.db is not None:
        try:
            query: Dict[str, Any] = {}
            if classification:
                query["classification"] = classification
            if search:
                query["$or"] = [
                    {"url": {"$regex": search, "$options": "i"}},
                    {"domain": {"$regex": search, "$options": "i"}},
                ]

            total = await db_manager.db.scans.count_documents(query)
            cursor = (
                db_manager.db.scans.find(query)
                .sort("created_at", -1)
                .skip(skip)
                .limit(limit)
            )
            items = [_format_doc(doc) async for doc in cursor]
            return items, total
        except Exception:
            pass

    # In-memory filtering
    filtered = IN_MEMORY_SCANS
    if classification:
        filtered = [s for s in filtered if s.get("classification") == classification]
    if search:
        s_lower = search.lower()
        filtered = [
            s for s in filtered
            if s_lower in s.get("url", "").lower() or s_lower in s.get("domain", "").lower()
        ]

    total = len(filtered)
    items = [_format_doc(s) for s in filtered[skip : skip + limit]]
    return items, total


async def delete_scan_record(scan_id: str) -> bool:
    """Deletes a specific scan record by ID."""
    deleted = False
    if db_manager.is_connected and db_manager.db is not None:
        try:
            query = {"_id": ObjectId(scan_id)} if ObjectId.is_valid(scan_id) else {"_id": scan_id}
            res = await db_manager.db.scans.delete_one(query)
            if res.deleted_count > 0:
                deleted = True
        except Exception:
            pass

    # Also remove from in-memory if present
    global IN_MEMORY_SCANS
    initial_len = len(IN_MEMORY_SCANS)
    IN_MEMORY_SCANS = [s for s in IN_MEMORY_SCANS if s.get("id") != scan_id and str(s.get("_id")) != scan_id]
    if len(IN_MEMORY_SCANS) < initial_len:
        deleted = True

    return deleted


async def calculate_dashboard_stats() -> Dict[str, Any]:
    """Calculates overall metrics, risk distribution, and top flagged indicators."""
    total = 0
    phishing = 0
    suspicious = 0
    low_risk = 0
    total_score = 0.0
    factor_counts: Dict[str, int] = {}

    all_scans = []

    if db_manager.is_connected and db_manager.db is not None:
        try:
            cursor = db_manager.db.scans.find({})
            async for doc in cursor:
                all_scans.append(doc)
        except Exception:
            all_scans = IN_MEMORY_SCANS
    else:
        all_scans = IN_MEMORY_SCANS

    total = len(all_scans)
    for s in all_scans:
        c = s.get("classification")
        if c == LABEL_PHISHING:
            phishing += 1
        elif c == LABEL_SUSPICIOUS:
            suspicious += 1
        elif c == LABEL_LOW_RISK:
            low_risk += 1

        total_score += float(s.get("risk_score", 0))

        # Tally risk factors
        explanation = s.get("explanation", {})
        factors = explanation.get("risk_factors", [])
        for f in factors:
            fname = f.get("factor", "Unknown")
            factor_counts[fname] = factor_counts.get(fname, 0) + 1

    avg_score = round(total_score / total, 1) if total > 0 else 0.0
    p_pct = round((phishing / total) * 100, 1) if total > 0 else 0.0
    s_pct = round((suspicious / total) * 100, 1) if total > 0 else 0.0
    l_pct = round((low_risk / total) * 100, 1) if total > 0 else 0.0

    top_factors = [
        {"factor": k, "count": v}
        for k, v in sorted(factor_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    ]

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "low_risk_count": low_risk,
        "phishing_percentage": p_pct,
        "suspicious_percentage": s_pct,
        "low_risk_percentage": l_pct,
        "average_risk_score": avg_score,
        "top_flagged_factors": top_factors,
        "is_database_connected": db_manager.is_connected,
    }
