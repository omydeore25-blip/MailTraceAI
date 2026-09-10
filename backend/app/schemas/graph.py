from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    type: str # email, sender, ip, domain, asn, nameserver, hash, campaign
    label: str
    threat_level: str = "clean" # clean, suspicious, malicious, critical
    details: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str # ROUTED_FROM, RESOLVES_TO, HOSTED_BY, HAS_IOC, ATTRIBUTED_TO
    style: Optional[Dict[str, Any]] = None
    animated: bool = False


class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_nodes: int
    total_edges: int
    source_engine: str = "neo4j" # "neo4j" or "postgres_fallback"
