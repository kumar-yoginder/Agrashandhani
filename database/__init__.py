"""
Threat Intelligence Database Manager

Supports three backends selected by environment variables:
  1. MongoDB  – set MONGODB_URI (e.g. mongodb://localhost:27017/threatintel)
  2. PostgreSQL – set POSTGRES_URI (e.g. postgresql://user:pass@host/db)
  3. JSON file  – fallback when neither URI is set (original behaviour)
"""
import os
import json
import atexit
from abc import ABC, abstractmethod
from config import DB_FILE, MONGODB_URI, POSTGRES_URI


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseDB(ABC):
    """Abstract interface every backend must implement."""

    @abstractmethod
    def get(self, query: str) -> dict:
        """Return the stored result for *query*, or None if not present."""

    @abstractmethod
    def exists(self, query: str) -> bool:
        """Return True if *query* is already stored."""

    @abstractmethod
    def set(self, query: str, data: dict):
        """Persist *data* under *query*."""

    def close(self):
        """Optional teardown hook (e.g. close connections)."""


# ---------------------------------------------------------------------------
# JSON (original) backend
# ---------------------------------------------------------------------------

class JsonDB(BaseDB):
    """Manages threat intelligence using a local JSON file (original behaviour)."""

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self._db = self._load()
        atexit.register(self.save_db)

    def _load(self) -> dict:
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "r") as fh:
                    return json.load(fh)
            except Exception as exc:
                print(f"[DB-JSON] Error loading DB: {exc}")
        return {}

    def save_db(self):
        """Flush in-memory cache to disk."""
        try:
            with open(self.db_file, "w") as fh:
                json.dump(self._db, fh, indent=2)
        except Exception as exc:
            print(f"[DB-JSON] Error saving DB: {exc}")

    def get(self, query: str) -> dict:
        return self._db.get(query)

    def exists(self, query: str) -> bool:
        return query in self._db

    def set(self, query: str, data: dict):
        self._db[query] = data
        # Persist immediately so the on-disk file stays current.
        self.save_db()


# ---------------------------------------------------------------------------
# MongoDB backend
# ---------------------------------------------------------------------------

class MongoDBDB(BaseDB):
    """
    Stores threat intelligence in a MongoDB collection.

    Connection string format:  mongodb[+srv]://[user:pass@]host[:port]/dbname
    The database and collection names are derived from the URI; if the URI
    does not specify a database name the default ``threatintel`` is used.

    Collection: ``threat_intel``
    Each document uses the IOC string as ``_id``.
    """

    COLLECTION = "threat_intel"

    def __init__(self, uri: str):
        try:
            from pymongo import MongoClient
            from pymongo.errors import ConnectionFailure
        except ImportError:
            raise RuntimeError(
                "pymongo is required for MongoDB support. "
                "Install it with: pip install pymongo"
            )

        self._client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Verify connection early so we fail fast with a clear message.
        try:
            self._client.admin.command("ping")
        except ConnectionFailure as exc:
            self._client.close()
            raise RuntimeError(f"[DB-MongoDB] Cannot connect to MongoDB: {exc}") from exc

        # Resolve database name from URI or fall back to default.
        db_name = self._client.get_default_database().name if self._resolve_db_name(uri) else "threatintel"
        self._col = self._client[db_name][self.COLLECTION]

        # Create a unique index on _id (it already exists by default in MongoDB,
        # so this is a no-op but makes intent explicit).
        self._col.create_index("_id", unique=True)
        print(f"[DB-MongoDB] Connected – db={db_name}, collection={self.COLLECTION}")

    @staticmethod
    def _resolve_db_name(uri: str) -> bool:
        """Return True if the URI contains a non-empty database path component."""
        # Quick heuristic: strip scheme, credentials, host; check for a '/dbname' part.
        try:
            from urllib.parse import urlparse
            parsed = urlparse(uri)
            return bool(parsed.path and parsed.path.strip("/"))
        except Exception:
            return False

    def get(self, query: str) -> dict:
        doc = self._col.find_one({"_id": query})
        if doc is None:
            return None
        doc.pop("_id", None)
        return doc

    def exists(self, query: str) -> bool:
        return self._col.count_documents({"_id": query}, limit=1) > 0

    def set(self, query: str, data: dict):
        document = dict(data)
        document["_id"] = query
        self._col.replace_one({"_id": query}, document, upsert=True)

    def close(self):
        self._client.close()


# ---------------------------------------------------------------------------
# PostgreSQL backend
# ---------------------------------------------------------------------------

class PostgresDB(BaseDB):
    """
    Stores threat intelligence in a PostgreSQL table.

    Connection string format:  postgresql://user:pass@host[:port]/dbname

    Table schema (auto-created on first use):
        CREATE TABLE IF NOT EXISTS threat_intel (
            query     TEXT PRIMARY KEY,
            data      JSONB NOT NULL,
            timestamp TIMESTAMPTZ DEFAULT now()
        );
    """

    TABLE = "threat_intel"

    def __init__(self, uri: str):
        try:
            import psycopg2
            import psycopg2.extras
            import psycopg2.sql as pgsql
        except ImportError:
            raise RuntimeError(
                "psycopg2 is required for PostgreSQL support. "
                "Install it with: pip install psycopg2-binary"
            )

        try:
            self._conn = psycopg2.connect(uri)
            self._conn.autocommit = True
        except Exception as exc:
            raise RuntimeError(f"[DB-Postgres] Cannot connect to PostgreSQL: {exc}") from exc

        self._psycopg2 = psycopg2
        self._extras = psycopg2.extras
        self._sql = pgsql
        self._init_schema()
        print(f"[DB-Postgres] Connected – table={self.TABLE}")

    def _init_schema(self):
        """Create the table and index if they do not already exist."""
        tbl = self._sql.Identifier(self.TABLE)
        idx = self._sql.Identifier(f"{self.TABLE}_timestamp_idx")
        with self._conn.cursor() as cur:
            cur.execute(
                self._sql.SQL("""
                    CREATE TABLE IF NOT EXISTS {tbl} (
                        query     TEXT PRIMARY KEY,
                        data      JSONB NOT NULL,
                        timestamp TIMESTAMPTZ DEFAULT now()
                    );
                """).format(tbl=tbl)
            )
            cur.execute(
                self._sql.SQL("""
                    CREATE INDEX IF NOT EXISTS {idx} ON {tbl} (timestamp DESC);
                """).format(idx=idx, tbl=tbl)
            )

    def get(self, query: str) -> dict:
        tbl = self._sql.Identifier(self.TABLE)
        with self._conn.cursor() as cur:
            cur.execute(
                self._sql.SQL("SELECT data FROM {tbl} WHERE query = %s;").format(tbl=tbl),
                (query,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        # psycopg2 already deserialises JSONB to a Python dict.
        return row[0]

    def exists(self, query: str) -> bool:
        tbl = self._sql.Identifier(self.TABLE)
        with self._conn.cursor() as cur:
            cur.execute(
                self._sql.SQL("SELECT 1 FROM {tbl} WHERE query = %s LIMIT 1;").format(tbl=tbl),
                (query,),
            )
            return cur.fetchone() is not None

    def set(self, query: str, data: dict):
        tbl = self._sql.Identifier(self.TABLE)
        with self._conn.cursor() as cur:
            cur.execute(
                self._sql.SQL("""
                    INSERT INTO {tbl} (query, data, timestamp)
                    VALUES (%s, %s, now())
                    ON CONFLICT (query) DO UPDATE
                        SET data = EXCLUDED.data,
                            timestamp = now();
                """).format(tbl=tbl),
                (query, self._extras.Json(data)),
            )

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Backwards-compatible wrapper
# ---------------------------------------------------------------------------

class ThreatIntelDB:
    """
    Public façade kept for backwards compatibility.

    Delegates all operations to the appropriate backend chosen by
    :func:`_get_db_backend`.  Existing call-sites are unaffected.
    """

    def __init__(self):
        self._backend: BaseDB = _get_db_backend()
        atexit.register(self._backend.close)

    # ------------------------------------------------------------------
    # Public API (unchanged from original JsonDB-based class)
    # ------------------------------------------------------------------

    def get(self, query: str) -> dict:
        """Return the stored result for *query*, or None."""
        return self._backend.get(query)

    def exists(self, query: str) -> bool:
        """Return True if *query* is already stored."""
        return self._backend.exists(query)

    def set(self, query: str, data: dict):
        """Persist *data* under *query*."""
        self._backend.set(query, data)

    def save_db(self):
        """
        Flush any in-memory state to persistent storage.

        For JSON backend this writes the file; for MongoDB/PostgreSQL it
        is a no-op because every :meth:`set` call is already durable.
        """
        if isinstance(self._backend, JsonDB):
            self._backend.save_db()


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def _get_db_backend() -> BaseDB:
    """
    Select and initialise the appropriate database backend.

    Priority:
      1. MongoDB  if MONGODB_URI is set and non-empty
      2. PostgreSQL if POSTGRES_URI is set and non-empty
      3. JSON file  (original behaviour, always available)
    """
    if MONGODB_URI:
        try:
            backend = MongoDBDB(MONGODB_URI)
            return backend
        except Exception as exc:
            print(f"[DB] MongoDB init failed, falling back to JSON: {exc}")

    if POSTGRES_URI:
        try:
            backend = PostgresDB(POSTGRES_URI)
            return backend
        except Exception as exc:
            print(f"[DB] PostgreSQL init failed, falling back to JSON: {exc}")

    return JsonDB(DB_FILE)


# ---------------------------------------------------------------------------
# Global instance (used by engine/__init__.py)
# ---------------------------------------------------------------------------
db_manager = ThreatIntelDB()
