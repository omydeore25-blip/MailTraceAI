import React, { useState } from "react";
import { Search, Globe, Link as LinkIcon, HardDrive, FileCode, ShieldAlert, ShieldCheck } from "lucide-react";
import { ExtractedIOCs } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface IOCDataTableProps {
  iocs: ExtractedIOCs | null;
}

export const IOCDataTable: React.FC<IOCDataTableProps> = ({ iocs }) => {
  const [filter, setFilter] = useState<"all" | "url" | "ip" | "domain" | "attachment">("all");
  const [search, setSearch] = useState("");

  if (!iocs) return null;

  // Flatten all IOCs into a unified list
  const allItems: Array<{
    type: string;
    value: string;
    defanged: string;
    score: number;
    malicious: boolean;
    details: string;
  }> = [];

  iocs.urls.forEach((u) => {
    allItems.push({
      type: "url",
      value: u.value,
      defanged: u.defanged_value,
      score: u.reputation_score,
      malicious: u.is_malicious,
      details: u.enrichment?.categories?.join(", ") || "Standard Web Link",
    });
  });

  iocs.ips.forEach((i) => {
    allItems.push({
      type: "ip",
      value: i.value,
      defanged: i.defanged_value,
      score: i.reputation_score,
      malicious: i.is_malicious,
      details: `${i.enrichment?.country || "US"} • ${i.enrichment?.isp || i.enrichment?.org || "Host"}`,
    });
  });

  iocs.domains.forEach((d) => {
    allItems.push({
      type: "domain",
      value: d.value,
      defanged: d.defanged_value,
      score: d.reputation_score,
      malicious: d.is_malicious,
      details: d.enrichment?.typosquatting?.reason || d.enrichment?.registrar || "Domain Record",
    });
  });

  iocs.attachments.forEach((a) => {
    allItems.push({
      type: "attachment",
      value: a.sha256,
      defanged: a.filename,
      score: a.risk_level === "Critical" ? 100 : a.risk_level === "High" ? 75 : 0,
      malicious: a.risk_level === "Critical" || a.risk_level === "High",
      details: `${a.content_type} • ${a.risk_flags.join("; ") || "Clean Attachment"}`,
    });
  });

  const filteredItems = allItems.filter((item) => {
    const matchesType = filter === "all" || item.type === filter;
    const matchesSearch =
      item.defanged.toLowerCase().includes(search.toLowerCase()) ||
      item.details.toLowerCase().includes(search.toLowerCase());
    return matchesType && matchesSearch;
  });

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "url":
        return <LinkIcon className="w-3.5 h-3.5 text-blue-400" />;
      case "ip":
        return <Globe className="w-3.5 h-3.5 text-indigo-400" />;
      case "domain":
        return <HardDrive className="w-3.5 h-3.5 text-emerald-400" />;
      case "attachment":
        return <FileCode className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return null;
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <CardTitle>
          <Search className="w-4 h-4 text-blue-400" />
          Extracted Indicators of Compromise & Threat Intelligence ({allItems.length})
        </CardTitle>

        {/* Filters & Search */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex bg-slate-950/60 p-1 rounded-lg border border-slate-800 text-xs">
            {(["all", "url", "ip", "domain", "attachment"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setFilter(t)}
                className={`px-2.5 py-1 rounded capitalize transition-colors ${
                  filter === t ? "bg-blue-600 text-white font-semibold" : "text-slate-400 hover:text-white"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IOCs..."
              className="h-8 pl-8 pr-3 text-xs bg-slate-950/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {filteredItems.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-400">No indicators matching your filter.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                  <th className="pb-3 pl-2">Type</th>
                  <th className="pb-3">Defanged Indicator</th>
                  <th className="pb-3">Intelligence & Context</th>
                  <th className="pb-3">Reputation</th>
                  <th className="pb-3 pr-2 text-right">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {filteredItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 pl-2">
                      <span className="flex items-center gap-1.5 capitalize text-slate-300 font-medium">
                        {getTypeIcon(item.type)}
                        {item.type}
                      </span>
                    </td>
                    <td className="py-3 font-mono text-slate-200 max-w-xs truncate pr-4">
                      {item.defanged}
                    </td>
                    <td className="py-3 text-slate-400 text-[11px] pr-4">
                      {item.details}
                    </td>
                    <td className="py-3 font-mono">
                      <span className={item.score >= 60 ? "text-red-400 font-bold" : item.score >= 30 ? "text-amber-400" : "text-slate-400"}>
                        {item.score.toFixed(0)}/100
                      </span>
                    </td>
                    <td className="py-3 pr-2 text-right">
                      {item.malicious ? (
                        <Badge variant="destructive" className="gap-1 text-[10px]">
                          <ShieldAlert className="w-3 h-3" /> Malicious
                        </Badge>
                      ) : (
                        <Badge variant="success" className="gap-1 text-[10px]">
                          <ShieldCheck className="w-3 h-3" /> Clean
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
