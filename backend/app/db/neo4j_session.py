from typing import Optional
from neo4j import AsyncGraphDatabase, AsyncDriver
from app.core.config import settings
from app.core.logging import logger

_neo4j_driver: Optional[AsyncDriver] = None


async def get_neo4j_driver() -> Optional[AsyncDriver]:
    global _neo4j_driver
    if not settings.NEO4J_ENABLED:
        return None

    if _neo4j_driver is None:
        try:
            _neo4j_driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            # Verify connectivity
            await _neo4j_driver.verify_connectivity()
            logger.info("Connected successfully to Neo4j database.")
        except Exception as e:
            logger.warning(f"Neo4j connection failed or disabled ({e}). Falling back to PostgreSQL relational graph.")
            _neo4j_driver = None
    return _neo4j_driver


async def close_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver:
        await _neo4j_driver.close()
        _neo4j_driver = None
        logger.info("Neo4j driver closed.")


async def is_neo4j_available() -> bool:
    driver = await get_neo4j_driver()
    return driver is not None
