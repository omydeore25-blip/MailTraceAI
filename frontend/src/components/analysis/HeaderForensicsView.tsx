import React, { useState } from "react";
import { Terminal, AlertTriangle, Check, ChevronDown, ChevronUp, Copy } from "lucide-react";
import { HeaderForensicReport } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface HeaderForensicsViewProps {
  report: HeaderForensicReport | null;
  rawHeaders?: string | null;
}

export const HeaderForensicsView: React.FC<HeaderForensicsViewProps> = ({ report, rawHeaders }) => {
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!report) return null;

  const copyHeaders = () => {
    if (rawHeaders) {
      navigator.clipboard.writeText(rawHeaders);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>
          <Terminal className="w-4 h-4 text-blue-400" />
          RFC 5322 Header Forensics & Spoofing Audit
        </CardTitle>
        <div className="flex items-center gap-2">
          {report.has_spoofed_headers ? (
            <Badge variant="destructive" className="gap-1">
              <AlertTriangle className="w-3 h-3" /> Spoofing Flags ({report.spoofing_indicators.length})
            </Badge>
          ) : (
            <Badge variant="success" className="gap-1">
              <Check className="w-3 h-3" /> Headers Coherent
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Spoofing Alerts if any */}
        {report.spoofing_indicators.length > 0 && (
          <div className="space-y-2">
            {report.spoofing_indicators.map((ind, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-200 flex items-start gap-2.5"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{ind}</span>
              </div>
            ))}
          </div>
        )}

        {/* Essential Header Comparison Matrix */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">From Header:</span>
            <div className="font-mono text-slate-200 truncate">{report.from_header}</div>
            {report.from_name && <div className="text-[11px] text-slate-400 mt-1">Display Name: "{report.from_name}"</div>}
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Reply-To Route:</span>
            <div className={`font-mono truncate ${report.reply_to ? "text-amber-400 font-semibold" : "text-slate-400"}`}>
              {report.reply_to || "(Omitted - Defaults to From)"}
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Envelope Return-Path:</span>
            <div className="font-mono text-slate-200 truncate">{report.return_path || "(Not Provided)"}</div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Originating Mailer / MUA:</span>
            <div className="font-mono text-slate-200 truncate">{report.mailer_client || "Standard SMTP Relay"}</div>
          </div>
        </div>

        {/* Toggle Raw RFC Headers */}
        {rawHeaders && (
          <div className="border-t border-slate-800 pt-3">
            <button
              onClick={() => setShowRaw(!showRaw)}
              className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
            >
              {showRaw ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              <span>{showRaw ? "Hide Raw RFC 5322 Headers" : "View Raw RFC 5322 Headers"}</span>
            </button>

            {showRaw && (
              <div className="mt-3 relative">
                <button
                  onClick={copyHeaders}
                  className="absolute right-3 top-3 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? "Copied" : "Copy"}</span>
                </button>
                <pre className="p-4 rounded-lg bg-slate-950 border border-slate-850 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
                  {rawHeaders}
                </pre>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
