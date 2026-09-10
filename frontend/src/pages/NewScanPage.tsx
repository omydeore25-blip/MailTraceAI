import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { EmailUploadZone } from "../components/analysis/EmailUploadZone";
import { RiskScoreBanner } from "../components/analysis/RiskScoreBanner";
import { AuthBadgeGrid } from "../components/analysis/AuthBadgeGrid";
import { HopTimelineView } from "../components/analysis/HopTimelineView";
import { HeaderForensicsView } from "../components/analysis/HeaderForensicsView";
import { IOCDataTable } from "../components/analysis/IOCDataTable";
import { AIInsightCard } from "../components/analysis/AIInsightCard";
import { AttributionCard } from "../components/analysis/AttributionCard";
import { ThreatGraphCanvas } from "../components/graph/ThreatGraphCanvas";
import { GeoHopMap } from "../components/map/GeoHopMap";
import { EmailAnalysisDetail, GraphData } from "../types";
import { apiClient } from "../lib/api-client";
import { Shield, Sparkles } from "lucide-react";

export const NewScanPage: React.FC = () => {
  const [analysis, setAnalysis] = useState<EmailAnalysisDetail | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalysisComplete = async (data: EmailAnalysisDetail) => {
    setAnalysis(data);
    // Fetch associated infrastructure graph
    try {
      if (data.id && data.id !== "temp-id") {
        const g = await apiClient.getGraph(data.id);
        setGraphData(g);
      }
    } catch {
      // Graph fallback
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <Shield className="w-6 h-6 text-blue-500" />
          Autonomous Email Threat Examination
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Upload an RFC 822/5322 <span className="text-blue-400 font-mono">.eml</span> file, Outlook <span className="text-blue-400 font-mono">.msg</span> file, or choose a benchmark threat preset below.
        </p>
      </div>

      {/* Ingestion Box */}
      <EmailUploadZone
        onAnalysisComplete={handleAnalysisComplete}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
      />

      {/* If Analysis Available, Render Complete Forensic Dashboard */}
      {analysis && (
        <div className="space-y-8 pt-4 border-t border-slate-800 animate-in fade-in duration-500">
          {/* Executive Risk Score Banner */}
          <RiskScoreBanner assessment={analysis.risk_assessment} />

          {/* Authentication Protocols */}
          <AuthBadgeGrid auth={analysis.auth_summary} />

          {/* Infrastructure Graph */}
          {graphData && <ThreatGraphCanvas graphData={graphData} />}

          {/* Geo Relay Map */}
          <GeoHopMap hops={analysis.hops} />

          {/* Hop Timeline & RFC Header Forensics */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <HopTimelineView hops={analysis.hops} />
            <HeaderForensicsView report={analysis.headers_report} rawHeaders={analysis.raw_headers || analysis.headers_report?.from_header} />
          </div>

          {/* AI NLP Intent & Attribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <AIInsightCard insights={analysis.ai_insights} />
            <AttributionCard
              analysisId={analysis.id}
              campaignId={analysis.campaign_id}
              threatActor={analysis.threat_actor}
              mitreAttack={analysis.mitre_attack || []}
            />
          </div>

          {/* Extracted IOC Data Table */}
          <IOCDataTable iocs={analysis.extracted_iocs} />
        </div>
      )}
    </div>
  );
};
