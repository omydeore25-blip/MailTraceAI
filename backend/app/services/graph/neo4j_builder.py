from typing import Dict, Any, Optional
from app.db.neo4j_session import get_neo4j_driver
from app.schemas.graph import GraphData
from app.core.logging import logger


async def sync_analysis_to_neo4j(analysis_data: Dict[str, Any]) -> bool:
    """Synchronize email analysis nodes and edges into Neo4j graph database."""
    driver = await get_neo4j_driver()
    if not driver:
        return False

    email_id = str(analysis_data.get("id"))
    subject = analysis_data.get("subject") or "No Subject"
    sender = analysis_data.get("sender", "unknown")
    risk_score = float(analysis_data.get("risk_score", 0.0))
    threat_level = str(analysis_data.get("threat_level", "Clean"))
    campaign_id = analysis_data.get("campaign_id") or "CAMP-NONE"
    threat_actor = analysis_data.get("threat_actor") or "Unattributed"

    try:
        async with driver.session() as session:
            # 1. Merge Email and Sender
            cypher_email = """
            MERGE (e:Email {id: $email_id})
            SET e.subject = $subject, e.risk_score = $risk_score, e.threat_level = $threat_level
            MERGE (s:Sender {email: $sender})
            MERGE (e)-[:SENT_FROM]->(s)
            MERGE (c:Campaign {id: $campaign_id})
            MERGE (e)-[:PART_OF_CAMPAIGN]->(c)
            MERGE (a:ThreatActor {name: $threat_actor})
            MERGE (c)-[:ATTRIBUTED_TO]->(a)
            """
            await session.run(
                cypher_email,
                email_id=email_id,
                subject=subject,
                risk_score=risk_score,
                threat_level=threat_level,
                sender=sender,
                campaign_id=campaign_id,
                threat_actor=threat_actor
            )

            # 2. Merge Hops (IPs)
            hops = analysis_data.get("hops", []) or analysis_data.get("hop_timeline", [])
            prev_id = email_id
            for hop in hops:
                ip = hop.get("ip") if isinstance(hop, dict) else getattr(hop, "ip", None)
                if ip:
                    cypher_ip = """
                    MATCH (source {id: $prev_id})
                    MERGE (ipNode:IPAddress {ip: $ip})
                    MERGE (source)-[:ROUTED_THROUGH]->(ipNode)
                    """
                    await session.run(cypher_ip, prev_id=prev_id, ip=ip)
                    prev_id = ip

            # 3. Merge IOCs
            iocs = analysis_data.get("iocs", [])
            for item in iocs:
                itype = item.get("ioc_type")
                ival = item.get("value")
                score = float(item.get("reputation_score", 0.0))
                if itype == "url":
                    await session.run("""
                    MATCH (e:Email {id: $email_id})
                    MERGE (u:URL {url: $val})
                    SET u.reputation_score = $score
                    MERGE (e)-[:CONTAINS_URL]->(u)
                    """, email_id=email_id, val=ival, score=score)
                elif itype == "domain":
                    await session.run("""
                    MATCH (e:Email {id: $email_id})
                    MERGE (d:Domain {domain: $val})
                    SET d.reputation_score = $score
                    MERGE (e)-[:RESOLVES_TO_DOMAIN]->(d)
                    """, email_id=email_id, val=ival, score=score)

        return True
    except Exception as e:
        logger.warning(f"Neo4j sync failed: {e}")
        return False
