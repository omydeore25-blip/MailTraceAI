# MailTrace AI — Autonomous Email Forensics & Threat Attribution Platform
**Smart India Hackathon (SIH) 2026**

---

## 1. Executive Summary & Problem Statement

**MailTrace AI** is an enterprise-grade cyber-forensic investigation platform designed to ingest raw email artifacts (`.eml`, `.msg`, and raw MIME text), dissect routing infrastructures across multi-hop relay timelines, verify cryptographic and DNS authentication records (SPF, DKIM, DMARC, ARC), enrich extracted indicators of compromise (IOCs) with global threat intelligence, apply NLP/deep-learning models for intent and phishing classification, reconstruct transit latency timelines, map correlated malicious infrastructure into graph representations, attribute campaigns to threat actors (MITRE ATT&CK), and generate court-/audit-ready forensic PDF/JSON reports.

---

## 2. Core Forensic Workflow Pipeline

```
Email Ingestion (.eml / .msg / Raw MIME)
  │
  ▼
Deterministic MIME & Attachment Parsing (Hashed with MD5/SHA1/SHA256 & Magic Bytes)
  │
  ▼
Reverse-Chronological Header Forensics (MTA Hops, Latency Delays, Clock Skew)
  │
  ▼
Cryptographic Authentication Protocol Audit (SPF, DKIM, DMARC, ARC Verification)
  │
  ▼
Indicator of Compromise (IOC) Extraction (URLs, IPs, Domains, Typosquatting)
  │
  ▼
Dual-Mode Threat Intelligence Enrichment (VirusTotal v3, AbuseIPDB, IPinfo + Mock Fallback)
  │
  ▼
AI/NLP Threat Detection (Social Engineering Intent, Financial BEC, Credential Harvest)
  │
  ▼
Explainable Multi-Factor Risk Scoring Engine (0 to 100 Weighted Score)
  │
  ▼
Campaign Correlation & Threat Actor Attribution (Subnet Clustering & MITRE ATT&CK)
  │
  ▼
Infrastructure Relationship Graph (Neo4j Engine with PostgreSQL Fallback)
  │
  ▼
Forensic Visualizations (Interactive Graph, Hop Latency Timeline, GeoIP Relay Map)
  │
  ▼
Audit-Ready Reporting (Pixel-Perfect ReportLab PDF & SIEM/SOAR JSON Export)
```

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons |
| **Backend** | Python 3.11, FastAPI (Async), Uvicorn, Pydantic V2 |
| **Database** | PostgreSQL 16 (Primary) / Async SQLite Fallback |
| **Graph DB** | Neo4j 5 (Cypher) with PostgreSQL JSONB CTE Fallback |
| **AI / NLP** | Rule-based Heuristic Scorer + Linguistic Intent Classifier |
| **Threat Intelligence** | VirusTotal v3, AbuseIPDB v2, IPinfo / GeoIP, Mock Fallback Engine |
| **Forensic PDF** | ReportLab PDF Engine (Court-ready audit document) |
| **Containerization** | Docker Compose (Multi-container: Postgres, Neo4j, Backend, Frontend) |

---

## 4. Real APIs vs. Local/Demo Fallback Architecture

To ensure **100% presentation reliability** during SIH hackathon evaluations and in air-gapped environments, MailTrace AI features an automated failover architecture:

| Component | Primary Live Integration | Fallback / Demo Mode |
| :--- | :--- | :--- |
| **Email Authentication** | Live DNS over UDP (`dnspython` for SPF/DKIM/DMARC) | Header `Authentication-Results` parser + domain lookup |
| **IP Reputation** | **AbuseIPDB API v2** (`/api/v2/check`) | Pre-indexed CIDR abuse database + Tor exit nodes |
| **URL / Hash Intel** | **VirusTotal API v3** (`/api/v3`) | Offline signature dictionary + heuristic URL analyzer |
| **GeoIP / ASN** | **IPinfo API** | Offline deterministic coordinate & ASN resolver |
| **Graph Engine** | **Neo4j 5** via Bolt protocol | **PostgreSQL Relational / JSONB CTE Graph Builder** |
| **Reporting** | **ReportLab** (Local Python Engine) | Self-contained offline generation (No external APIs needed) |

---

## 5. Quick Start & Execution Guide

### Option A: Local Development (Instant Setup)

#### 1. Backend Setup
```bash
# Navigate to backend
cd backend

# Create & activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at: `http://127.0.0.1:8000/docs`.

#### 2. Seed Sample Forensic Cases
```bash
# In project root, run the seeding script:
python scripts/seed_samples.py
```

#### 3. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install packages
npm install

# Start Vite development server
npm run dev
```
Open `http://localhost:5173` in your browser.

---

### Option B: Full-Stack Docker Compose
```bash
# Start all 4 containers (PostgreSQL, Neo4j, Backend, Frontend)
docker compose up -d

# Verify containers are running
docker compose ps
```
- **Frontend Dashboard**: `http://localhost:5173`
- **Backend Swagger API**: `http://localhost:8000/docs`
- **Neo4j Browser**: `http://localhost:7474` (User: `neo4j`, Password: `password`)

---

## 6. SIH Benchmark Test Scenarios

The platform includes 4 pre-configured forensic scenarios available via one-click preset buttons on the **New Scan** page:

1. **Clean Newsletter (`clean_newsletter.eml`)**:
   - **Verdict**: Clean (Score: 0.0/100).
   - **Checks**: SPF Pass, DKIM Pass, DMARC Pass, Clean URLs, 0 anomalous delays.
2. **Credential Harvester Phishing (`credential_phishing.eml`)**:
   - **Verdict**: Critical/Malicious (Score: ~79/100).
   - **Checks**: Typosquatted domain (`micros0ft-security-auth.com`), DMARC Reject, Mapped MITRE T1566.002, T1598.003, T1078.
3. **VIP Executive Impersonation / BEC (`bec_wire_fraud.eml`)**:
   - **Verdict**: Suspicious / BEC Threat (Score: ~53/100).
   - **Checks**: CEO display-name deception, wire transfer urgency triggers, attributed to *Cosmic Lynx / BEC Syndicate*.
4. **Forged Transit / Spoofed PayPal (`dkim_spf_spoofed.eml`)**:
   - **Verdict**: Malicious (Score: ~74/100).
   - **Checks**: Forged Received headers, backward timestamp clock skew (-15m), DMARC failure.

---

## 7. REST API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System status, DB connectivity, Neo4j availability, and TI status |
| `POST` | `/api/v1/auth/login` | Authenticate forensic analyst & issue JWT bearer token |
| `POST` | `/api/v1/analysis/upload` | Upload `.eml` or `.msg` file for full forensic pipeline execution |
| `POST` | `/api/v1/analysis/paste` | Analyze raw MIME or email header text |
| `GET` | `/api/v1/analysis/` | List recent forensic cases (paginated) |
| `GET` | `/api/v1/analysis/{id}` | Detailed forensic report, hops, auth, IOCs, and AI insights |
| `GET` | `/api/v1/graph/analysis/{id}` | Retrieve infrastructure graph nodes & edges (React Flow format) |
| `GET` | `/api/v1/threat-intel/lookup` | Standalone lookup for IP, Domain, URL, or File Hash |
| `GET` | `/api/v1/reports/{id}/pdf` | Download court-ready ReportLab forensic PDF report |
| `GET` | `/api/v1/reports/{id}/json` | Export structured case file for SIEM / SOAR ingestion |

---

## 8. Authors & Acknowledgments
Built for **Smart India Hackathon (SIH) 2026** by the **MailTrace AI Team**.
Specializing in Next-Gen Cyber Defense, Email Forensics, and Adversarial Attribution.
