"""
Threat Intelligence Database Manager
"""
import os
import json
import atexit
from config import DB_FILE


class ThreatIntelDB:
    """Manages threat intelligence database with persistence"""
    
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.db = self._load_db()
        atexit.register(self.save_db)
    
    def _load_db(self) -> dict:
        """Load database from JSON file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading DB: {e}")
                return {}
        return {}
    
    def save_db(self):
        """Save database to JSON file"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.db, f, indent=2)
        except Exception as e:
            print(f"Error saving DB: {e}")
    
    def get(self, query: str) -> dict:
        """Get entry from database"""
        return self.db.get(query)
    
    def exists(self, query: str) -> bool:
        """Check if query exists in database"""
        return query in self.db
    
    def set(self, query: str, data: dict):
        """Set entry in database"""
        self.db[query] = data


# Global database instance
db_manager = ThreatIntelDB()
