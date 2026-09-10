export interface ReceivedHop {
  hop_number: number;
  from_host: string | null;
  by_host: string | null;
  ip: string | null;
  asn: string | null;
  country: string | null;
  region?: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  org?: string | null;
  isp?: string | null;
  timestamp: string | null;
  delay_seconds: number;
  anomalous: boolean;
  anomaly_reason: string | null;
  is_private?: boolean;
  geo_status?: string | null;
  geo_error?: string | null;
}

export interface HeaderForensicReport {
  subject: string | null;
  message_id: string | null;
  date: string | null;
  from_header: string;
  from_name: string | null;
  from_domain: string;
  reply_to: string | null;
  return_path: string | null;
  to: string[];
  cc: string[];
  mailer_client: string | null;
  hops: ReceivedHop[];
  spoofing_indicators: string[];
  has_spoofed_headers: boolean;
  total_transit_time_seconds: number;
}

export interface SPFResult {
  status: string;
  record: string | null;
  client_ip: string | null;
  evaluated_domain: string | null;
  aligned: boolean;
  details: string | null;
  verification_method?: string;
}

export interface DKIMResult {
  status: string;
  selector: string | null;
  domain: string | null;
  algorithm: string | null;
  aligned: boolean;
  signature_found: boolean;
  details: string | null;
  verification_method?: string;
}

export interface DMARCResult {
  status: string;
  policy: string | null;
  subdomain_policy: string | null;
  percentage: number;
  spf_aligned: boolean;
  dkim_aligned: boolean;
  record: string | null;
  details: string | null;
  verification_method?: string;
}

export interface ARCResult {
  status: string;
  chain_validated: boolean;
  details: string | null;
  verification_method?: string;
}


export interface AuthSummary {
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  arc: ARCResult;
  overall_authenticated: boolean;
  failure_reasons: string[];
}

export interface IOCItem {
  ioc_type: string;
  value: string;
  defanged_value: string;
  reputation_score: number;
  is_malicious: boolean;
  enrichment: Record<string, any>;
}

export interface AttachmentMeta {
  filename: string;
  content_type: string;
  size_bytes: number;
  md5: string;
  sha1: string;
  sha256: string;
  is_executable_or_script: boolean;
  is_archive: boolean;
  is_macro_enabled: boolean;
  risk_level: string;
  risk_flags: string[];
}

export interface ExtractedIOCs {
  urls: IOCItem[];
  ips: IOCItem[];
  domains: IOCItem[];
  attachments: AttachmentMeta[];
  total_iocs_found: number;
  malicious_iocs_count: number;
}

export interface RiskFactor {
  category: string;
  weight_percentage: number;
  score: number;
  weighted_contribution: number;
  description: string;
  flagged_items: string[];
}

export interface RiskScoreResult {
  overall_score: number;
  threat_level: "Clean" | "Suspicious" | "Malicious" | "Critical";
  summary: string;
  factors: RiskFactor[];
  recommended_action: string;
}

export interface EmailAnalysisOverview {
  id: string;
  message_id: string | null;
  subject: string | null;
  sender: string;
  from_name: string | null;
  email_date: string | null;
  risk_score: number;
  threat_level: "Clean" | "Suspicious" | "Malicious" | "Critical";
  campaign_id: string | null;
  threat_actor: string | null;
  created_at: string;
}

export interface AnalystAlert {
  id: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  title: string;
  description: string;
  evidence: string;
  source: string;
  related_ioc?: string | null;
  analysis_id?: string | null;
  timestamp?: string | null;
}

export interface EmailAnalysisDetail extends EmailAnalysisOverview {
  recipients: string[];
  reply_to: string | null;
  return_path: string | null;
  body_plain: string | null;
  body_html: string | null;
  raw_headers?: string | null;
  headers_report: HeaderForensicReport | null;
  auth_summary: AuthSummary | null;
  extracted_iocs: ExtractedIOCs | null;
  risk_assessment: RiskScoreResult | null;
  ai_insights: Record<string, any>;
  mitre_attack: Array<{
    id: string;
    name: string;
    tactic: string;
    confidence: string;
    evidence: string;
  }>;
  hops: ReceivedHop[];
  attachments: AttachmentMeta[];
  alerts?: AnalystAlert[];
  graph?: GraphData | null;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  threat_level: string;
  details: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  animated?: boolean;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
  source_engine: string;
}
