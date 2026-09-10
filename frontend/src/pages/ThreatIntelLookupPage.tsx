import React, { useState } from "react";
import { Search, Globe, Link as LinkIcon, HardDrive, FileCode, ShieldAlert, ShieldCheck, Loader2, Info } from "lucide-react";
import { apiClient } from "../lib/api-client";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";

export const ThreatIntelLookupPage: React.FC = () => {
  const [iocType, setIocType] = useState<"ip" | "domain" | "url" | "hash">("ip");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await apiClient.lookupIOC(iocType, value.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.response?.data?.error || "Threat intelligence lookup query failed.");
    } finally {
      setLoading(false);
    }
  };

  const loadExample = (type: "ip" | "domain" | "url" | "hash", val: string) => {
    setIocType(type);
    setValue(val);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <Search className="w-6 h-6 text-blue-500" />
          Threat Intelligence Cross-Correlation Console
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Query suspicious IPs, domains, URLs, or attachment hashes against VirusTotal v3, AbuseIPDB, IPinfo, and local threat databases.
        </p>
      </div>

      {/* Query Form */}
      <Card>
        <CardContent className="p-6">
          <form onSubmit={handleLookup} className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Indicator Category:</span>
              <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                {(["ip", "domain", "url", "hash"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setIocType(t)}
                    className={`px-3 py-1 rounded uppercase font-mono transition-colors ${
                      iocType === t ? "bg-blue-600 text-white font-semibold" : "text-slate-400 hover:text-white"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={
                  iocType === "ip"
                    ? "Enter IPv4 address (e.g., 185.220.101.5 or 8.8.8.8)..."
                    : iocType === "domain"
                    ? "Enter domain name (e.g., micros0ft-security-auth.com)..."
                    : iocType === "url"
                    ? "Enter full URL (e.g., https://micros0ft-security-auth.com/login)..."
                    : "Enter SHA256 or MD5 hash..."
                }
                className="flex-1 h-11 px-4 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
              <Button type="submit" disabled={loading} size="lg" className="gap-2">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                <span>Investigate</span>
              </Button>
            </div>

            {/* Quick Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-2 text-[11px] font-mono text-slate-400">
              <span>Benchmark Queries:</span>
              <button
                type="button"
                onClick={() => loadExample("ip", "185.220.101.5")}
                className="px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-800/40 hover:bg-red-900/40"
              >
                Tor Exit Node (IP)
              </button>
              <button
                type="button"
                onClick={() => loadExample("domain", "micros0ft-security-auth.com")}
                className="px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-800/40 hover:bg-red-900/40"
              >
                Phish Domain
              </button>
              <button
                type="button"
                onClick={() => loadExample("ip", "8.8.8.8")}
                className="px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40 hover:bg-emerald-900/40"
              >
                Google DNS (Clean)
              </button>
            </div>
          </form>
        </CardContent>
      </Card>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/50 border border-red-800 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Intelligence Results Card */}
      {result && (
        <Card className="animate-in fade-in duration-300">
          <CardHeader className="flex flex-row items-center justify-between border-b border-slate-800">
            <CardTitle>
              <Info className="w-4 h-4 text-blue-400" />
              Intelligence Dossier: {result.value}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge
                variant={result.enrichment?.is_malicious ? "destructive" : "success"}
                className="text-xs"
              >
                {result.enrichment?.is_malicious ? "Malicious / Reported" : "Clean / Unflagged"}
              </Badge>
              <span className="text-xs font-mono font-bold text-white bg-slate-800 px-2.5 py-1 rounded">
                Reputation: {result.enrichment?.reputation_score?.toFixed(0) || 0}/100
              </span>
            </div>
          </CardHeader>
          <CardContent className="p-6 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 font-mono">
                <span className="text-[10px] text-slate-400 block mb-1">Intelligence Provider:</span>
                <span className="text-blue-400 font-bold">{result.enrichment?.provider || "Aggregator Engine"}</span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 font-mono">
                <span className="text-[10px] text-slate-400 block mb-1">Location / ISP:</span>
                <span className="text-slate-200">
                  {result.enrichment?.city ? `${result.enrichment.city}, ` : ""}
                  {result.enrichment?.country || "N/A"}
                  {result.enrichment?.isp && <span className="text-slate-400 text-[10px] block truncate">{result.enrichment.isp}</span>}
                </span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 font-mono">
                <span className="text-[10px] text-slate-400 block mb-1">Total Reports / Detections:</span>
                <span className="text-slate-200">
                  {result.enrichment?.total_reports !== undefined
                    ? `${result.enrichment.total_reports} Abuse Reports`
                    : result.enrichment?.positives !== undefined
                    ? `${result.enrichment.positives} Positives`
                    : "No Global Reports"}
                </span>
              </div>
            </div>

            {/* Raw JSON Intelligence */}
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Full Provider Metadata:</span>
              <pre className="p-4 rounded-xl bg-slate-950 font-mono text-[11px] text-slate-300 border border-slate-800 overflow-x-auto max-h-80 leading-relaxed">
                {JSON.stringify(result.enrichment, null, 2)}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
