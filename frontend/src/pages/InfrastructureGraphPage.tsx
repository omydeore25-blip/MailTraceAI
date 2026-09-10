import React, { useEffect, useState } from "react";
import { Network, Search, AlertCircle, Loader2 } from "lucide-react";
import { apiClient } from "../lib/api-client";
import { EmailAnalysisOverview, GraphData } from "../types";
import { ThreatGraphCanvas } from "../components/graph/ThreatGraphCanvas";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/card";

export const InfrastructureGraphPage: React.FC = () => {
  const [scans, setScans] = useState<EmailAnalysisOverview[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.getRecentScans(30).then((data) => {
      setScans(data);
      if (data.length > 0) {
        setSelectedScanId(data[0].id);
      }
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedScanId) return;
    apiClient.getGraph(selectedScanId).then(setGraphData).catch(() => setGraphData(null));
  }, [selectedScanId]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Network className="w-6 h-6 text-blue-500" />
            Infrastructure Attribution & Topology Graph
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Visualizing relationships between relay MTAs, source subnets, extracted domain infrastructure, and threat actor campaign clusters.
          </p>
        </div>

        {/* Case Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Select Case:</span>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500 font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.subject ? s.subject.slice(0, 32) : "No Subject"} ({s.threat_level})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
        </div>
      ) : scans.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center text-xs text-slate-400">
            No analysis cases available yet. Launch a scan on the New Scan tab to generate infrastructure graphs.
          </CardContent>
        </Card>
      ) : (
        <ThreatGraphCanvas graphData={graphData} />
      )}
    </div>
  );
};
