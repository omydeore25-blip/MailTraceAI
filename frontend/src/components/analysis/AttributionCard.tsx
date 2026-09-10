import React from "react";
import { Crosshair, Download, FileText, Code2, Users, ShieldAlert } from "lucide-react";
import { Button } from "../ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";
import { apiClient } from "../../lib/api-client";

interface AttributionCardProps {
  analysisId: string;
  campaignId: string | null;
  threatActor: string | null;
  mitreAttack: Array<{
    id: string;
    name: string;
    tactic: string;
    confidence: string;
    evidence: string;
  }>;
}

export const AttributionCard: React.FC<AttributionCardProps> = ({
  analysisId,
  campaignId,
  threatActor,
  mitreAttack,
}) => {
  return (
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <CardTitle>
          <Crosshair className="w-4 h-4 text-red-400" />
          Threat Attribution & MITRE ATT&CK Matrix
        </CardTitle>

        {/* Report Exports */}
        <div className="flex items-center gap-2">
          <a
            href={apiClient.getPdfUrl(analysisId)}
            download
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic PDF</span>
          </a>
          <a
            href={apiClient.getJsonUrl(analysisId)}
            download
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>SIEM JSON</span>
          </a>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Campaign & Threat Actor Profiling */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Campaign Cluster ID:</span>
            <div className="font-mono text-sm font-bold text-blue-400">{campaignId || "Uncorrelated"}</div>
            <p className="text-[11px] text-slate-400 mt-1">Clustered via relay subnet and selector fingerprints.</p>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Attributed Threat Actor:</span>
            <div className="font-bold text-sm text-red-400 flex items-center gap-1.5">
              <Users className="w-4 h-4" />
              <span>{threatActor || "Unattributed Adversary"}</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Historical TTP and infrastructure alignment.</p>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix */}
        <div>
          <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">
            Mapped Adversarial Techniques ({mitreAttack.length}):
          </span>

          {mitreAttack.length === 0 ? (
            <div className="text-xs text-slate-400 bg-slate-900/40 p-3 rounded-lg border border-slate-850">
              No adversarial techniques identified.
            </div>
          ) : (
            <div className="space-y-2">
              {mitreAttack.map((tech) => (
                <div
                  key={tech.id}
                  className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-blue-400 bg-blue-950/60 border border-blue-800/60 px-2 py-0.5 rounded text-[10px]">
                        {tech.id}
                      </span>
                      <span className="font-semibold text-white">{tech.name}</span>
                      <span className="text-slate-400 text-[10px]">({tech.tactic})</span>
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">{tech.evidence}</p>
                  </div>
                  <Badge variant="outline" className="text-[10px] shrink-0 self-start sm:self-center">
                    Confidence: {tech.confidence}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
