import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Shield, ShieldAlert, ShieldCheck, Activity, Users, ArrowUpRight, UploadCloud, ChevronRight, Clock } from "lucide-react";
import { apiClient } from "../lib/api-client";
import { EmailAnalysisOverview } from "../types";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";

export const DashboardPage: React.FC = () => {
  const [scans, setScans] = useState<EmailAnalysisOverview[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient
      .getRecentScans(50)
      .then(setScans)
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  const totalScans = scans.length;
  const criticalCount = scans.filter((s) => s.threat_level === "Critical" || s.threat_level === "Malicious").length;
  const cleanCount = scans.filter((s) => s.threat_level === "Clean").length;
  const uniqueCampaigns = new Set(scans.map((s) => s.campaign_id).filter(Boolean)).size;


  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="rounded-2xl border border-blue-500/20 bg-gradient-to-r from-blue-950/40 via-slate-900/60 to-slate-950 p-8 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono mb-3">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            Autonomous Threat Intel Active
          </div>
          <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
            MailTrace AI Security Operations Center
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-2 max-w-2xl leading-relaxed">
            Autonomous multi-hop forensic inspection, cryptographic protocol verification (SPF/DKIM/DMARC/ARC), NLP-driven BEC detection, and adversarial infrastructure attribution.
          </p>
        </div>

        <Link to="/scan">
          <Button size="lg" className="gap-2 shadow-xl shadow-blue-600/30">
            <UploadCloud className="w-4 h-4" />
            <span>Launch New Examination</span>
          </Button>
        </Link>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Total Inspected</span>
              <div className="text-2xl font-black font-mono text-white">{totalScans}</div>
            </div>
            <div className="p-3 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Activity className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Threats Blocked</span>
              <div className="text-2xl font-black font-mono text-red-400">{criticalCount}</div>
            </div>
            <div className="p-3 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Verified Clean</span>
              <div className="text-2xl font-black font-mono text-emerald-400">{cleanCount}</div>
            </div>
            <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Attribution Clusters</span>
              <div className="text-2xl font-black font-mono text-purple-400">{uniqueCampaigns} Active</div>
            </div>
            <div className="p-3 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Users className="w-5 h-5" />
            </div>
          </CardContent>
        </Card>

      </div>

      {/* Recent Cases Section */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>
            <Clock className="w-4 h-4 text-blue-400" />
            Recent Forensic Examinations
          </CardTitle>
          <Link to="/history" className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1">
            <span>View All History</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-12 text-slate-400 text-xs">Loading case records...</div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12 text-slate-400 text-xs space-y-3">
              <p>No email scans in history yet.</p>
              <Link to="/scan">
                <Button size="sm">Start First Scan</Button>
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                    <th className="pb-3 pl-2">Subject / Message</th>
                    <th className="pb-3">Sender (From)</th>
                    <th className="pb-3">Risk Score</th>
                    <th className="pb-3">Verdict</th>
                    <th className="pb-3">Attributed Campaign</th>
                    <th className="pb-3 pr-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {scans.slice(0, 8).map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">

                      <td className="py-3.5 pl-2 max-w-xs">
                        <Link to={`/analysis/${scan.id}`} className="font-semibold text-white hover:text-blue-400 transition-colors truncate block">
                          {scan.subject || "(No Subject)"}
                        </Link>
                        <span className="text-[10px] text-slate-400 font-mono">ID: {scan.id.slice(0, 8)}</span>
                      </td>
                      <td className="py-3.5 font-mono text-slate-300 max-w-[200px] truncate">
                        {scan.sender}
                      </td>
                      <td className="py-3.5 font-mono">
                        <span className={scan.risk_score >= 60 ? "text-red-400 font-bold" : scan.risk_score >= 30 ? "text-amber-400" : "text-emerald-400"}>
                          {scan.risk_score.toFixed(0)}/100
                        </span>
                      </td>
                      <td className="py-3.5">
                        <Badge
                          variant={scan.threat_level === "Critical" || scan.threat_level === "Malicious" ? "destructive" : scan.threat_level === "Suspicious" ? "warning" : "success"}
                          className="text-[10px]"
                        >
                          {scan.threat_level}
                        </Badge>
                      </td>
                      <td className="py-3.5 font-mono text-slate-400 text-[11px]">
                        {scan.campaign_id || "None"}
                      </td>
                      <td className="py-3.5 pr-2 text-right">
                        <Link to={`/analysis/${scan.id}`}>
                          <Button size="sm" variant="outline" className="h-7 text-[11px] gap-1">
                            <span>Inspect</span>
                            <ArrowUpRight className="w-3 h-3" />
                          </Button>
                        </Link>
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
