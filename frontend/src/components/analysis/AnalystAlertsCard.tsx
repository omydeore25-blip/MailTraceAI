import React, { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  Copy,
  Check,
  Search,
  Filter,
  Layers,
} from "lucide-react";
import { AnalystAlert } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface AnalystAlertsCardProps {
  alerts?: AnalystAlert[];
}

export const AnalystAlertsCard: React.FC<AnalystAlertsCardProps> = ({ alerts = [] }) => {
  const [filter, setFilter] = useState<string>("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const severityCounts = {
    ALL: alerts.length,
    Critical: alerts.filter((a) => a.severity === "Critical").length,
    High: alerts.filter((a) => a.severity === "High").length,
    Medium: alerts.filter((a) => a.severity === "Medium").length,
    Low: alerts.filter((a) => a.severity === "Low").length,
    Informational: alerts.filter((a) => a.severity === "Informational").length,
  };

  const filteredAlerts =
    filter === "ALL" ? alerts : alerts.filter((a) => a.severity.toUpperCase() === filter.toUpperCase());

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-950/80 text-red-300 border border-red-700/80 uppercase tracking-wider">
            <ShieldAlert className="w-3 h-3 text-red-400" />
            Critical
          </span>
        );
      case "high":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-orange-950/80 text-orange-300 border border-orange-700/80 uppercase tracking-wider">
            <AlertTriangle className="w-3 h-3 text-orange-400" />
            High
          </span>
        );
      case "medium":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/80 text-amber-300 border border-amber-700/80 uppercase tracking-wider">
            <AlertCircle className="w-3 h-3 text-amber-400" />
            Medium
          </span>
        );
      case "low":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-950/80 text-blue-300 border border-blue-700/80 uppercase tracking-wider">
            <Info className="w-3 h-3 text-blue-400" />
            Low
          </span>
        );
      case "informational":
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-800 text-slate-300 border border-slate-700 uppercase tracking-wider">
            <Info className="w-3 h-3 text-slate-400" />
            Info
          </span>
        );
    }
  };

  const getBorderColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "border-l-4 border-l-red-500 border-red-900/40 bg-red-950/15";
      case "high":
        return "border-l-4 border-l-orange-500 border-orange-900/40 bg-orange-950/15";
      case "medium":
        return "border-l-4 border-l-amber-500 border-amber-900/40 bg-amber-950/15";
      case "low":
        return "border-l-4 border-l-blue-500 border-blue-900/40 bg-blue-950/15";
      default:
        return "border-l-4 border-l-slate-600 border-slate-800 bg-slate-900/30";
    }
  };

  return (
    <Card className="overflow-hidden border border-slate-800">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <CardTitle className="text-base sm:text-lg flex items-center gap-2 text-white">
              Real-Time Security Analyst Alerts
              <Badge variant="outline" className="text-xs font-mono">
                {alerts.length} Total
              </Badge>
            </CardTitle>
            <p className="text-xs text-slate-400">
              Correlated actionable findings based on multi-vector forensic inspection.
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {(["ALL", "Critical", "High", "Medium", "Low", "Informational"] as const).map((lvl) => {
            const count = severityCounts[lvl];
            const isActive = filter.toUpperCase() === lvl.toUpperCase();
            return (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors font-mono flex items-center gap-1.5 ${
                  isActive
                    ? "bg-blue-600 text-white shadow"
                    : "bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800"
                }`}
              >
                <span>{lvl === "ALL" ? "All Alerts" : lvl}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                    isActive ? "bg-blue-800 text-white" : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </CardHeader>

      <CardContent className="p-4 sm:p-6 space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="py-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-emerald-950/60 border border-emerald-800/80 flex items-center justify-center mx-auto text-emerald-400">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-200">
                {alerts.length === 0
                  ? "No Security Threats or Anomalies Detected"
                  : `No ${filter} Alerts Found`}
              </p>
              <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                {alerts.length === 0
                  ? "This email passed sender authentication checks and heuristic intent screening without generating critical or malicious alerts."
                  : `There are currently no alerts classified under the ${filter} severity tier.`}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 rounded-xl border transition-all ${getBorderColor(
                  alert.severity
                )} shadow-sm hover:shadow-md space-y-2.5`}
              >
                {/* Header line */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    {getSeverityBadge(alert.severity)}
                    <span className="font-bold text-sm text-white tracking-tight">
                      {alert.title}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                    <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                      Source: {alert.source}
                    </span>
                    {alert.timestamp && (
                      <span className="hidden md:inline text-slate-500">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    )}
                  </div>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-300 leading-relaxed">
                  {alert.description}
                </p>

                {/* Evidence Callout */}
                <div className="bg-slate-950/80 rounded-lg p-2.5 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1 font-semibold">
                    <Layers className="w-3 h-3 text-blue-400" />
                    Forensic Evidence & Context:
                  </div>
                  <div className="text-slate-200 break-words whitespace-pre-wrap leading-relaxed">
                    {alert.evidence}
                  </div>
                </div>

                {/* Related IOC footer chip if present */}
                {alert.related_ioc && (
                  <div className="flex items-center justify-between pt-1 border-t border-slate-800/50">
                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 truncate max-w-[85%]">
                      <span className="text-slate-500">Related IOC:</span>
                      <span className="text-blue-400 font-semibold truncate">
                        {alert.related_ioc}
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopy(alert.related_ioc!, alert.id)}
                      className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors shrink-0"
                      title="Copy Related IOC"
                    >
                      {copiedId === alert.id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
