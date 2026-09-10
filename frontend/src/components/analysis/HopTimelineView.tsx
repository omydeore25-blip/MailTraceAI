import React from "react";
import { GitCommit, Clock, AlertTriangle, Globe, ArrowDown } from "lucide-react";
import { ReceivedHop } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface HopTimelineViewProps {
  hops: ReceivedHop[];
}

export const HopTimelineView: React.FC<HopTimelineViewProps> = ({ hops }) => {
  if (!hops || hops.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-center text-slate-400 text-xs">
          No transit Received headers detected in the message.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Clock className="w-4 h-4 text-blue-400" />
          Forensic Relay Hop Timeline (Origin to Edge Mail Gateway)
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800">
          {hops.map((hop, index) => {
            const isOrigin = index === 0;
            const isDestination = index === hops.length - 1;

            return (
              <div key={hop.hop_number} className="relative group">
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-[23px] top-1.5 w-4 h-4 rounded-full border-2 flex items-center justify-center transition-transform group-hover:scale-125 ${
                    hop.anomalous
                      ? "border-red-500 bg-red-950 text-red-400"
                      : isOrigin
                      ? "border-blue-500 bg-blue-950 text-blue-400"
                      : "border-slate-700 bg-slate-900 text-slate-400"
                  }`}
                >
                  <span className="text-[9px] font-bold">{hop.hop_number}</span>
                </div>

                {/* Hop Card */}
                <div
                  className={`border rounded-xl p-4 transition-colors ${
                    hop.anomalous
                      ? "bg-red-950/20 border-red-900/40"
                      : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-xs text-white">
                        Hop #{hop.hop_number}: {isOrigin ? "Origin Client / MUA" : isDestination ? "Edge Gateway" : "Transit Relay"}
                      </span>
                      {hop.anomalous && (
                        <Badge variant="destructive" className="gap-1 text-[10px]">
                          <AlertTriangle className="w-3 h-3" /> Anomaly Flagged
                        </Badge>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                      {hop.delay_seconds > 0 && (
                        <span className="flex items-center gap-1 text-slate-300">
                          <Clock className="w-3 h-3 text-blue-400" /> +{hop.delay_seconds}s latency
                        </span>
                      )}
                      <span>{hop.timestamp ? new Date(hop.timestamp).toLocaleTimeString() : "No Timestamp"}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono">
                    <div className="bg-slate-900/60 p-2 rounded border border-slate-850">
                      <span className="text-slate-400 text-[10px] block">IP Address:</span>
                      <span className="text-blue-400 font-semibold">{hop.ip || "Unknown IP"}</span>
                    </div>
                    <div className="bg-slate-900/60 p-2 rounded border border-slate-850">
                      <span className="text-slate-400 text-[10px] block">Location & ASN:</span>
                      <span className="text-slate-200">
                        {hop.city ? `${hop.city}, ${hop.country}` : hop.country || "Unknown Country"}
                        {hop.asn && <span className="text-slate-400 text-[10px] block truncate">{hop.asn}</span>}
                      </span>
                    </div>
                    <div className="bg-slate-900/60 p-2 rounded border border-slate-850">
                      <span className="text-slate-400 text-[10px] block">Relaying MTA:</span>
                      <span className="text-slate-300 truncate block">{hop.by_host || hop.from_host || "Direct Delivery"}</span>
                    </div>
                  </div>

                  {hop.anomaly_reason && (
                    <div className="mt-2.5 p-2 rounded bg-red-900/30 border border-red-800/40 text-red-300 text-xs flex items-center gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span>{hop.anomaly_reason}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
};
