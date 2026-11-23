import aiosqlite
import json
from datetime import datetime, timezone

DB_PATH = "security_audit.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score REAL NOT NULL,
                blocked_layer TEXT,
                category TEXT,
                total_latency_ms REAL NOT NULL,
                raw_prompt TEXT NOT NULL,
                normalized_prompt TEXT NOT NULL,
                stages_json TEXT NOT NULL
            )
        """)
        await db.commit()


async def log_event(event: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO audit_logs (
                timestamp, source, verdict, risk_score, blocked_layer,
                category, total_latency_ms, raw_prompt, normalized_prompt, stages_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event.get("source", "api"),
                event["verdict"],
                event["risk_score"],
                event.get("blocked_layer"),
                event.get("category", "Benign"),
                event["total_latency_ms"],
                event["raw_prompt"],
                event["normalized_prompt"],
                json.dumps(event["stages"]),
            ),
        )
        await db.commit()
        event["id"] = cursor.lastrowid
        event["timestamp"] = timestamp
    return event


async def get_recent_logs(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["stages"] = json.loads(item.pop("stages_json"))
                results.append(item)
            return results
