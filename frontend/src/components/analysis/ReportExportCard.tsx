import React from "react";
import { FileText, Code2, Download, ShieldCheck, Calendar, Hash } from "lucide-react";
import { apiClient } from "../../lib/api-client";
import { EmailAnalysisDetail } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface ReportExportCardProps {
  analysis: EmailAnalysisDetail;
}

export const ReportExportCard: React.FC<ReportExportCardProps> = ({ analysis }) => {
  return (
    <Card className="overflow-hidden border border-slate-800">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <CardTitle className="text-base sm:text-lg flex items-center gap-2 text-white">
              Forensic Evidence Reports & Exports
            </CardTitle>
            <p className="text-xs text-slate-400">
              Generate evidentiary incident response reports and machine-readable case exports.
            </p>
          </div>
        </div>

        <Badge variant="outline" className="font-mono text-xs text-slate-300">
          Case Ref: {analysis.id.slice(0, 8)}
        </Badge>
      </CardHeader>

      <CardContent className="p-4 sm:p-6 space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Case ID</span>
            <div className="text-slate-200 truncate font-semibold">{analysis.id}</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Threat Level</span>
            <div
              className={`font-semibold ${
                analysis.threat_level === "Critical" || analysis.threat_level === "Malicious"
                  ? "text-red-400"
                  : analysis.threat_level === "Suspicious"
                  ? "text-amber-400"
                  : "text-emerald-400"
              }`}
            >
              {analysis.threat_level} ({analysis.risk_score.toFixed(1)}/100)
            </div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Total Relays</span>
            <div className="text-slate-200 font-semibold">{analysis.hops?.length || 0} Hops</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase">Total IOCs</span>
            <div className="text-slate-200 font-semibold">
              {analysis.extracted_iocs?.total_iocs_found || 0} Extracted
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2">
          <a
            href={apiClient.getPdfUrl(analysis.id)}
            download
            className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg transition-all"
          >
            <FileText className="w-4 h-4" />
            <span>Download Official PDF Forensic Report</span>
          </a>

          <a
            href={apiClient.getJsonUrl(analysis.id)}
            download
            className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 shadow-md transition-all"
          >
            <Code2 className="w-4 h-4 text-blue-400" />
            <span>Export Machine-Readable JSON Dossier</span>
          </a>
        </div>
      </CardContent>
    </Card>
  );
};
