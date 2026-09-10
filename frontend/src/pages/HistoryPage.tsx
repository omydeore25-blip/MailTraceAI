import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { History, Search, ArrowUpRight, FileText, Code2, Loader2, Trash2 } from "lucide-react";
import { apiClient } from "../lib/api-client";
import { EmailAnalysisOverview } from "../types";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";

export const HistoryPage: React.FC = () => {
  const [scans, setScans] = useState<EmailAnalysisOverview[]>([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient
      .getRecentScans(100)
      .then(setScans)
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!window.confirm("Are you sure you want to delete this forensic case? This action cannot be undone.")) {
      return;
    }
    try {
      await apiClient.deleteAnalysis(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
    } catch (err) {
      alert("Failed to delete case.");
    }
  };


  const filteredScans = scans.filter((s) => {
    const matchesFilter = filter === "all" || s.threat_level.toLowerCase() === filter.toLowerCase();
    const matchesSearch =
      (s.subject || "").toLowerCase().includes(search.toLowerCase()) ||
      s.sender.toLowerCase().includes(search.toLowerCase()) ||
      (s.campaign_id || "").toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <History className="w-6 h-6 text-blue-500" />
            Forensic Examination Case History
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete audit trail of processed emails, threat classifications, and indicators of compromise.
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
            {["all", "critical", "malicious", "suspicious", "clean"].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded capitalize transition-colors ${
                  filter === f ? "bg-blue-600 text-white font-semibold" : "text-slate-400 hover:text-white"
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter cases..."
              className="h-8 pl-8 pr-3 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="text-center py-20">
              <Loader2 className="w-8 h-8 animate-spin text-blue-500 mx-auto" />
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="text-center py-16 text-slate-400 text-xs">
              No examination cases matching your criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-slate-950/40">
                    <th className="py-3.5 pl-4">Case / Subject</th>
                    <th className="py-3.5">Sender</th>
                    <th className="py-3.5">Risk Score</th>
                    <th className="py-3.5">Verdict</th>
                    <th className="py-3.5">Campaign ID</th>
                    <th className="py-3.5">Timestamp</th>
                    <th className="py-3.5 pr-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {filteredScans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3.5 pl-4 max-w-xs">
                        <Link
                          to={`/analysis/${scan.id}`}
                          className="font-semibold text-white hover:text-blue-400 transition-colors truncate block"
                        >
                          {scan.subject || "(No Subject)"}
                        </Link>
                        <span className="text-[10px] text-slate-400 font-mono">Ref: {scan.id.slice(0, 8)}</span>
                      </td>
                      <td className="py-3.5 font-mono text-slate-300 max-w-[180px] truncate">
                        {scan.sender}
                      </td>
                      <td className="py-3.5 font-mono">
                        <span
                          className={
                            scan.risk_score >= 60
                              ? "text-red-400 font-bold"
                              : scan.risk_score >= 30
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }
                        >
                          {scan.risk_score.toFixed(0)}/100
                        </span>
                      </td>
                      <td className="py-3.5">
                        <Badge
                          variant={
                            scan.threat_level === "Critical" || scan.threat_level === "Malicious"
                              ? "destructive"
                              : scan.threat_level === "Suspicious"
                              ? "warning"
                              : "success"
                          }
                          className="text-[10px]"
                        >
                          {scan.threat_level}
                        </Badge>
                      </td>
                      <td className="py-3.5 font-mono text-slate-400 text-[11px]">
                        {scan.campaign_id || "None"}
                      </td>
                      <td className="py-3.5 text-slate-400 text-[11px]">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3.5 pr-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <a
                            href={apiClient.getPdfUrl(scan.id)}
                            download
                            title="Download PDF"
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                          >
                            <FileText className="w-3.5 h-3.5" />
                          </a>
                          <a
                            href={apiClient.getJsonUrl(scan.id)}
                            download
                            title="Download JSON"
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                          >
                            <Code2 className="w-3.5 h-3.5" />
                          </a>
                          <button
                            onClick={(e) => handleDelete(scan.id, e)}
                            title="Delete Case"
                            className="p-1.5 rounded hover:bg-red-950/60 text-slate-400 hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                          <Link to={`/analysis/${scan.id}`}>
                            <Button size="sm" variant="outline" className="h-7 text-[11px] gap-1 ml-1">
                              <span>View</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </Button>
                          </Link>

                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
