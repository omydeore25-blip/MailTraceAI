from typing import Dict, Any, List
import urllib.parse
from app.schemas.graph import GraphNode, GraphEdge, GraphData


def build_postgres_graph(analysis_data: Dict[str, Any]) -> GraphData:
    """
    Construct a full infrastructure and threat relationship graph from actual email analysis records.
    Graph relationships represent the actual analyzed email:
    Email
    ├── Sender (Address)
    │     └── Domain
    ├── Recipient (Address)
    │     └── Domain
    ├── IP Address
    │     └── GeoLocation
    ├── URL
    │     ├── Domain
    │     └── Threat Intelligence (if flagged)
    ├── File Hash
    │     └── Threat Intelligence (if flagged)
    ├── MITRE Technique
    └── Campaign / Threat Actor
    """
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node: GraphNode):
        if node.id not in seen_nodes:
            seen_nodes.add(node.id)
            nodes.append(node)

    def add_edge(edge: GraphEdge):
        edge_key = f"{edge.source}->{edge.target}:{edge.label}"
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append(edge)

    email_id = str(analysis_data.get("id", "email-root"))
    subject = analysis_data.get("subject") or "Email Message"
    sender = analysis_data.get("sender", "unknown@sender")
    recipients = analysis_data.get("recipients", []) or []
    risk_score = float(analysis_data.get("risk_score", 0.0))
    threat_level = str(analysis_data.get("threat_level", "Clean")).lower()

    # 1. Root Email Node
    email_node_id = f"email:{email_id}"
    add_node(
        GraphNode(
            id=email_node_id,
            type="email",
            label=f"Email: {subject[:30]}..." if len(subject) > 30 else f"Email: {subject}",
            threat_level=threat_level,
            details={
                "subject": subject,
                "sender": sender,
                "recipients": recipients,
                "risk_score": risk_score,
                "threat_level": threat_level,
            },
        )
    )

    # 2. Sender Address & Sender Domain
    if sender and sender != "unknown":
        sender_id = f"address:{sender.lower()}"
        sender_threat = "malicious" if threat_level in ["malicious", "critical"] else ("suspicious" if risk_score >= 30 else "clean")
        add_node(
            GraphNode(
                id=sender_id,
                type="address",
                label=f"Sender: {sender}",
                threat_level=sender_threat,
                details={"address": sender, "role": "sender"},
            )
        )
        add_edge(
            GraphEdge(
                id=f"edge:{email_node_id}->{sender_id}",
                source=email_node_id,
                target=sender_id,
                label="SENT_BY",
            )
        )

        if "@" in sender:
            sender_dom = sender.split("@")[-1].lower().strip()
            sender_dom_id = f"domain:{sender_dom}"
            add_node(
                GraphNode(
                    id=sender_dom_id,
                    type="domain",
                    label=f"Domain: {sender_dom}",
                    threat_level=sender_threat,
                    details={"domain": sender_dom, "context": "sender_domain"},
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{sender_id}->{sender_dom_id}",
                    source=sender_id,
                    target=sender_dom_id,
                    label="USES_DOMAIN",
                )
            )

    # 3. Recipient Addresses & Domains
    for recip in recipients:
        if recip and isinstance(recip, str) and "@" in recip:
            recip_clean = recip.strip().lower()
            recip_id = f"address:{recip_clean}"
            add_node(
                GraphNode(
                    id=recip_id,
                    type="address",
                    label=f"To: {recip_clean}",
                    threat_level="clean",
                    details={"address": recip_clean, "role": "recipient"},
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{recip_id}",
                    source=email_node_id,
                    target=recip_id,
                    label="ADDRESSED_TO",
                )
            )

            recip_dom = recip_clean.split("@")[-1].strip()
            recip_dom_id = f"domain:{recip_dom}"
            add_node(
                GraphNode(
                    id=recip_dom_id,
                    type="domain",
                    label=f"Domain: {recip_dom}",
                    threat_level="clean",
                    details={"domain": recip_dom, "context": "recipient_domain"},
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{recip_id}->{recip_dom_id}",
                    source=recip_id,
                    target=recip_dom_id,
                    label="TARGETS_DOMAIN",
                )
            )

    # 4. IP Addresses (Hop Relays) & Geolocation
    hops = analysis_data.get("hops", []) or analysis_data.get("hop_timeline", [])
    for h in hops:
        ip = h.get("ip") if isinstance(h, dict) else getattr(h, "ip", None)
        if ip:
            hop_num = h.get("hop_number") if isinstance(h, dict) else getattr(h, "hop_number", 1)
            is_anom = h.get("anomalous") if isinstance(h, dict) else getattr(h, "anomalous", False)
            is_priv = h.get("is_private") if isinstance(h, dict) else getattr(h, "is_private", False)
            ip_id = f"ip:{ip}"
            ip_threat = "malicious" if is_anom else ("clean" if is_priv else ("suspicious" if risk_score >= 50 else "clean"))

            add_node(
                GraphNode(
                    id=ip_id,
                    type="ip",
                    label=f"Hop #{hop_num}: {ip}",
                    threat_level=ip_threat,
                    details={
                        "ip": ip,
                        "hop_number": hop_num,
                        "is_private": is_priv,
                        "from_host": h.get("from_host") if isinstance(h, dict) else getattr(h, "from_host", None),
                        "country": h.get("country") if isinstance(h, dict) else getattr(h, "country", None),
                    },
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{ip_id}",
                    source=email_node_id,
                    target=ip_id,
                    label="ROUTED_THROUGH",
                    animated=True,
                )
            )

            # Location node (only when real coordinates or real city/country exist)
            lat = h.get("latitude") if isinstance(h, dict) else getattr(h, "latitude", None)
            lon = h.get("longitude") if isinstance(h, dict) else getattr(h, "longitude", None)
            city = h.get("city") if isinstance(h, dict) else getattr(h, "city", None)
            country = h.get("country") if isinstance(h, dict) else getattr(h, "country", None)

            if lat is not None and lon is not None and not is_priv:
                loc_label = f"{city}, {country}" if city and country else (country or f"{lat:.2f}, {lon:.2f}")
                loc_id = f"location:{lat:.2f},{lon:.2f}"
                add_node(
                    GraphNode(
                        id=loc_id,
                        type="location",
                        label=f"Location: {loc_label}",
                        threat_level="clean",
                        details={
                            "city": city,
                            "country": country,
                            "latitude": lat,
                            "longitude": lon,
                            "asn": h.get("asn") if isinstance(h, dict) else getattr(h, "asn", None),
                        },
                    )
                )
                add_edge(
                    GraphEdge(
                        id=f"edge:{ip_id}->{loc_id}",
                        source=ip_id,
                        target=loc_id,
                        label="LOCATED_IN",
                    )
                )

    # 5. Extracted IOCs (URLs, Domains, Hashes) & Threat Intelligence
    iocs = analysis_data.get("iocs", [])
    if isinstance(iocs, dict):
        raw_items = []
        for itype in ["urls", "domains", "ips", "attachments"]:
            for item in iocs.get(itype, []):
                raw_items.append(item)
        iocs = raw_items

    for item in iocs:
        itype = item.get("ioc_type", "ioc") if isinstance(item, dict) else getattr(item, "ioc_type", "ioc")
        ival = item.get("value", "") if isinstance(item, dict) else getattr(item, "value", "")
        defanged = item.get("defanged_value", ival) if isinstance(item, dict) else getattr(item, "defanged_value", ival)
        score = float(item.get("reputation_score", 0.0) if isinstance(item, dict) else getattr(item, "reputation_score", 0.0))
        is_mal = bool(item.get("is_malicious", False) if isinstance(item, dict) else getattr(item, "is_malicious", False))

        if itype == "url" and ival:
            url_threat = "critical" if is_mal else ("suspicious" if score >= 35 else "clean")
            url_node_id = f"url:{ival}"
            add_node(
                GraphNode(
                    id=url_node_id,
                    type="url",
                    label=f"URL: {defanged[:32]}",
                    threat_level=url_threat,
                    details={"url": ival, "reputation_score": score, "is_malicious": is_mal},
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{url_node_id}",
                    source=email_node_id,
                    target=url_node_id,
                    label="CONTAINS_URL",
                )
            )

            # URL Domain
            try:
                parsed_url = urllib.parse.urlparse(ival)
                url_domain = parsed_url.netloc.split(":")[0].lower()
                if url_domain:
                    url_dom_id = f"domain:{url_domain}"
                    add_node(
                        GraphNode(
                            id=url_dom_id,
                            type="domain",
                            label=f"Domain: {url_domain}",
                            threat_level=url_threat,
                            details={"domain": url_domain, "context": "url_domain"},
                        )
                    )
                    add_edge(
                        GraphEdge(
                            id=f"edge:{url_node_id}->{url_dom_id}",
                            source=url_node_id,
                            target=url_dom_id,
                            label="RESOLVES_TO_DOMAIN",
                        )
                    )
            except Exception:
                pass

            # Threat Intel node if flagged
            if is_mal or score >= 50:
                ti_id = f"ti:url:{ival[:32]}"
                add_node(
                    GraphNode(
                        id=ti_id,
                        type="threat_intel",
                        label=f"Intel: Malicious ({score:.0f}/100)",
                        threat_level="critical",
                        details={"ioc": ival, "score": score, "classification": "Malicious"},
                    )
                )
                add_edge(
                    GraphEdge(
                        id=f"edge:{url_node_id}->{ti_id}",
                        source=url_node_id,
                        target=ti_id,
                        label="FLAGGED_BY_INTEL",
                    )
                )

        elif itype in ["sha256", "hash"] and ival:
            hash_threat = "critical" if is_mal or score >= 70 else ("suspicious" if score >= 30 else "clean")
            hash_node_id = f"hash:{ival}"
            add_node(
                GraphNode(
                    id=hash_node_id,
                    type="hash",
                    label=f"SHA256: {ival[:12]}...",
                    threat_level=hash_threat,
                    details={"sha256": ival, "reputation_score": score, "is_malicious": is_mal},
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{hash_node_id}",
                    source=email_node_id,
                    target=hash_node_id,
                    label="CONTAINS_FILE_HASH",
                )
            )
            if is_mal:
                ti_hash_id = f"ti:hash:{ival[:16]}"
                add_node(
                    GraphNode(
                        id=ti_hash_id,
                        type="threat_intel",
                        label="Intel: Confirmed Malware",
                        threat_level="critical",
                        details={"hash": ival, "classification": "Malicious Payload"},
                    )
                )
                add_edge(
                    GraphEdge(
                        id=f"edge:{hash_node_id}->{ti_hash_id}",
                        source=hash_node_id,
                        target=ti_hash_id,
                        label="FLAGGED_BY_INTEL",
                    )
                )

    # 6. Attachment File Hashes (from attachments list)
    attachments = analysis_data.get("attachments", []) or []
    for att in attachments:
        sha256 = att.get("sha256") if isinstance(att, dict) else getattr(att, "sha256", None)
        fname = att.get("filename") if isinstance(att, dict) else getattr(att, "filename", "attachment")
        risk_lvl = str(att.get("risk_level") if isinstance(att, dict) else getattr(att, "risk_level", "Low")).lower()
        if sha256:
            hash_id = f"hash:{sha256}"
            add_node(
                GraphNode(
                    id=hash_id,
                    type="hash",
                    label=f"File: {fname[:20]}",
                    threat_level="critical" if risk_lvl in ["high", "critical"] else "clean",
                    details={
                        "filename": fname,
                        "sha256": sha256,
                        "content_type": att.get("content_type") if isinstance(att, dict) else getattr(att, "content_type", ""),
                        "risk_level": risk_lvl,
                    },
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{hash_id}",
                    source=email_node_id,
                    target=hash_id,
                    label="ATTACHMENT",
                )
            )

    # 7. MITRE ATT&CK Techniques Mapped
    mitre_techniques = analysis_data.get("mitre_attack", []) or []
    for tech in mitre_techniques:
        tech_id = tech.get("id") if isinstance(tech, dict) else getattr(tech, "id", None)
        tech_name = tech.get("name") if isinstance(tech, dict) else getattr(tech, "name", "Technique")
        if tech_id:
            m_node_id = f"mitre:{tech_id}"
            add_node(
                GraphNode(
                    id=m_node_id,
                    type="mitre_technique",
                    label=f"ATT&CK: {tech_id}",
                    threat_level="suspicious" if tech.get("confidence") != "High" else "critical",
                    details={
                        "technique_id": tech_id,
                        "name": tech_name,
                        "tactic": tech.get("tactic") if isinstance(tech, dict) else getattr(tech, "tactic", ""),
                        "confidence": tech.get("confidence") if isinstance(tech, dict) else getattr(tech, "confidence", ""),
                    },
                )
            )
            add_edge(
                GraphEdge(
                    id=f"edge:{email_node_id}->{m_node_id}",
                    source=email_node_id,
                    target=m_node_id,
                    label="USES_TECHNIQUE",
                )
            )

    # 8. Campaign / Attribution (Only if real attribution exists)
    threat_actor = analysis_data.get("threat_actor")
    campaign_id = analysis_data.get("campaign_id")

    if campaign_id and campaign_id not in ["UNC-UNKNOWN", "None", "", None]:
        camp_node_id = f"campaign:{campaign_id}"
        add_node(
            GraphNode(
                id=camp_node_id,
                type="campaign",
                label=f"Campaign: {campaign_id}",
                threat_level="critical",
                details={"campaign_id": campaign_id},
            )
        )
        add_edge(
            GraphEdge(
                id=f"edge:{email_node_id}->{camp_node_id}",
                source=email_node_id,
                target=camp_node_id,
                label="ATTRIBUTED_TO_CAMPAIGN",
            )
        )

    if threat_actor and threat_actor not in ["Unattributed Adversary", "None", "", None]:
        actor_node_id = f"threat_actor:{threat_actor}"
        add_node(
            GraphNode(
                id=actor_node_id,
                type="threat_actor",
                label=f"Actor: {threat_actor}",
                threat_level="critical",
                details={"threat_actor": threat_actor, "campaign": campaign_id},
            )
        )
        add_edge(
            GraphEdge(
                id=f"edge:{email_node_id}->{actor_node_id}",
                source=email_node_id,
                target=actor_node_id,
                label="ATTRIBUTED_TO_ACTOR",
            )
        )
        if campaign_id and campaign_id not in ["UNC-UNKNOWN", "None", "", None]:
            add_edge(
                GraphEdge(
                    id=f"edge:{camp_node_id}->{actor_node_id}",
                    source=camp_node_id,
                    target=actor_node_id,
                    label="OPERATED_BY",
                )
            )

    return GraphData(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
        source_engine="postgres_fallback",
    )
