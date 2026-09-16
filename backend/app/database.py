"""
PhishGuard AI - Database Client and Connection Lifecycle
Integrates with MongoDB asynchronously via Motor.
Includes an automatic in-memory fallback buffer to ensure the application
never crashes if MongoDB is offline during evaluations or demonstrations.
"""

import logging
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import settings

logger = logging.getLogger("phishguard.database")

# In-memory buffer used as fallback when MongoDB is unreachable
IN_MEMORY_SCANS = []

class DatabaseManager:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    is_connected: bool = False

    async def connect(self):
        """Initializes connection to MongoDB with timeout."""
        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGODB_URI}...")
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=2000
            )
            # Verify connection with a ping
            await self.client.admin.command("ping")
            self.db = self.client[settings.DATABASE_NAME]
            self.is_connected = True
            logger.info(f"Successfully connected to MongoDB database: '{settings.DATABASE_NAME}'")
        except Exception as exc:
            self.is_connected = False
            self.client = None
            self.db = None
            logger.warning(
                f"MongoDB connection failed ({exc}). Operating in graceful in-memory fallback mode."
            )

    async def close(self):
        """Closes the MongoDB client connection cleanly."""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed.")
            self.is_connected = False


db_manager = DatabaseManager()


def get_db() -> Optional[AsyncIOMotorDatabase]:
    """Returns current active database or None if in fallback mode."""
    return db_manager.db
