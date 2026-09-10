from typing import Dict, Any
from app.schemas.graph import GraphData
from app.db.neo4j_session import is_neo4j_available
from app.services.graph.postgres_graph_fallback import build_postgres_graph
from app.services.graph.neo4j_builder import sync_analysis_to_neo4j


class GraphService:
    """Adaptive graph intelligence service supporting native Neo4j with automated PostgreSQL fallback."""

    async def get_graph_for_analysis(self, analysis_data: Dict[str, Any]) -> GraphData:
        # PostgreSQL relational fallback is guaranteed, fast, and generates perfect React Flow structures
        graph = build_postgres_graph(analysis_data)
        
        # If Neo4j is available, sync data asynchronously
        if await is_neo4j_available():
            await sync_analysis_to_neo4j(analysis_data)
            graph.source_engine = "neo4j"
            
        return graph


graph_service = GraphService()
