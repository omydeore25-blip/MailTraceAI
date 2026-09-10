import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Loader2, Calendar, Mail } from "lucide-react";
import { apiClient } from "../lib/api-client";
import { EmailAnalysisDetail, GraphData } from "../types";
import { RiskScoreBanner } from "../components/analysis/RiskScoreBanner";
import { AnalystAlertsCard } from "../components/analysis/AnalystAlertsCard";
import { AuthBadgeGrid } from "../components/analysis/AuthBadgeGrid";
import { HeaderForensicsView } from "../components/analysis/HeaderForensicsView";
import { HopTimelineView } from "../components/analysis/HopTimelineView";
import { GeoHopMap } from "../components/map/GeoHopMap";
import { ThreatGraphCanvas } from "../components/graph/ThreatGraphCanvas";
import { IOCDataTable } from "../components/analysis/IOCDataTable";
import { AIInsightCard } from "../components/analysis/AIInsightCard";
import { AttributionCard } from "../components/analysis/AttributionCard";
import { ReportExportCard } from "../components/analysis/ReportExportCard";
import { Button } from "../components/ui/button";

export const AnalysisDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [analysis, setAnalysis] = useState<EmailAnalysisDetail | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);

    Promise.all([
      apiClient.getAnalysis(id),
      apiClient.getGraph(id).catch(() => null),
    ])
      .then(([aData, gData]) => {
        setAnalysis(aData);
        setGraphData(gData || aData?.graph || null);
      })
      .catch((err) => {
        setError(err.response?.data?.detail || "Failed to retrieve forensic analysis case.");
      })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
        <p className="text-xs text-slate-400 font-mono">Retrieving forensic evidence record...</p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="text-center py-24 space-y-4">
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 max-w-md mx-auto text-xs text-red-300">
          {error || "Case record not found."}
        </div>
        <Link to="/history">
          <Button variant="outline" size="sm" className="gap-2">
            <ArrowLeft className="w-4 h-4" />
            <span>Return to History</span>
          </Button>
        </Link>
      </div>
    );
  }

  const effectiveGraph = graphData || analysis.graph || null;

  return (
    <div className="space-y-8 pb-12">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <Link
            to="/history"
            className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1 mb-1 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to History
          </Link>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-2 truncate">
            {analysis.subject || "(No Subject Header)"}
          </h1>
          <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5 truncate max-w-xs">
              <Mail className="w-3.5 h-3.5 text-blue-400 shrink-0" />
              <span className="text-slate-300">From:</span> {analysis.sender}
            </span>
            <span className="hidden sm:inline">•</span>
            <span className="flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              {new Date(analysis.created_at).toLocaleString()}
            </span>
            <span className="hidden sm:inline">•</span>
            <span className="text-slate-400">Case Ref: {analysis.id.slice(0, 8)}</span>
          </div>
        </div>
      </div>

      {/* 1. Risk Score */}
      <RiskScoreBanner assessment={analysis.risk_assessment} />

      {/* 2. 🚨 Alerts */}
      <AnalystAlertsCard alerts={analysis.alerts || []} />

      {/* 3. 🔐 Authentication */}
      <AuthBadgeGrid auth={analysis.auth_summary} />

      {/* 4. 🧬 Header Forensics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <HeaderForensicsView report={analysis.headers_report} rawHeaders={analysis.raw_headers} />
        <HopTimelineView hops={analysis.hops} />
      </div>

      {/* 5. 🌍 GeoLocation / Hop Map */}
      <GeoHopMap hops={analysis.hops} />

      {/* 6. 🕸️ Infrastructure Threat Graph */}
      {effectiveGraph && <ThreatGraphCanvas graphData={effectiveGraph} />}

      {/* 7. 🔍 IOCs & Threat Intelligence */}
      <IOCDataTable iocs={analysis.extracted_iocs} />

      {/* 8. 🤖 AI Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AIInsightCard insights={analysis.ai_insights} />
        {/* 9. 🎯 MITRE / Attribution */}
        <AttributionCard
          analysisId={analysis.id}
          campaignId={analysis.campaign_id}
          threatActor={analysis.threat_actor}
          mitreAttack={analysis.mitre_attack || []}
        />
      </div>

      {/* 10. 📄 Reports */}
      <ReportExportCard analysis={analysis} />
    </div>
  );
};
