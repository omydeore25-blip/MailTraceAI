import React from "react";
import {
  Globe,
  MapPin,
  ArrowRight,
  ShieldAlert,
  Server,
  Lock,
  Clock,
  ExternalLink,
  AlertCircle,
  Network,
  Info,
} from "lucide-react";
import { ReceivedHop } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface GeoHopMapProps {
  hops: ReceivedHop[];
}

export const GeoHopMap: React.FC<GeoHopMapProps> = ({ hops = [] }) => {
  // 1. Separate mapped public hops, unconfigured/errored public hops, and private hops
  const geoHops = hops.filter(
    (h) => h.latitude !== null && h.longitude !== null && !h.is_private
  );

  const publicUnmappedHops = hops.filter(
    (h) => !h.is_private && (h.latitude === null || h.longitude === null) && h.ip
  );

  const privateHops = hops.filter((h) => h.is_private || !h.ip);

  // Check if any public hop has an unconfigured IPinfo token error
  const hasUnconfiguredError = publicUnmappedHops.some(
    (h) =>
      h.geo_status === "unconfigured" ||
      (h.geo_error && h.geo_error.toLowerCase().includes("not configured"))
  );

  // Check if any public hop has a provider query error
  const hasProviderError = publicUnmappedHops.some(
    (h) => h.geo_status === "error" || (h.geo_error && !h.geo_error.toLowerCase().includes("not configured"))
  );

  // Convert lat/lon to percentage position on Equirectangular map projection
  // x: (-180 to 180) -> (0% to 100%)
  // y: (90 to -90) -> (0% to 100%)
  const toMapCoords = (lat: number, lon: number) => {
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return { x: Math.max(5, Math.min(95, x)), y: Math.max(5, Math.min(95, y)) };
  };

  return (
    <Card className="overflow-hidden border border-slate-800">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <CardTitle className="text-base sm:text-lg flex items-center gap-2 text-white">
              Global Email Relay GeoLocation & Transit Hop Map
              <Badge variant="outline" className="text-xs font-mono">
                {geoHops.length} Mapped / {hops.length} Total Hops
              </Badge>
            </CardTitle>
            <p className="text-xs text-slate-400">
              Deterministic geographical transit routing derived strictly from Received headers.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge
            variant="outline"
            className="text-[10px] font-mono bg-slate-900 border-slate-700 text-slate-300"
          >
            {geoHops.length > 0 ? "Live Coordinates Mapped" : "Zero Synthetic Data"}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="p-4 sm:p-6 space-y-6">
        {/* Unconfigured / Provider Warning Banner if applicable */}
        {publicUnmappedHops.length > 0 && (
          <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-800/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-start gap-3">
              <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <p className="text-xs font-semibold text-amber-200">
                  {hasUnconfiguredError
                    ? "GeoLocation unavailable — IPinfo API key not configured"
                    : hasProviderError
                    ? "GeoLocation unavailable — IPinfo lookup error"
                    : "External Geolocation Unavailable for Public Relay Hops"}
                </p>
                <p className="text-[11px] text-amber-300/80 leading-relaxed">
                  MailTrace AI never fabricates or simulates geographic coordinates. Public IPs
                  remain strictly labeled with verifiable network attribution until an IPinfo token
                  is configured.
                </p>
              </div>
            </div>
            <span className="shrink-0 text-[10px] font-mono px-2 py-1 rounded bg-amber-900/40 text-amber-300 border border-amber-700/60 self-start sm:self-auto">
              RFC 791 / Public IPs Verified
            </span>
          </div>
        )}

        {/* World Map SVG Display (rendered if valid coordinates exist) */}
        {geoHops.length > 0 ? (
          <div className="relative w-full aspect-[2/1] sm:aspect-[2.2/1] bg-slate-950 rounded-xl border border-slate-800 overflow-hidden shadow-inner">
            {/* World map outline background grid */}
            <svg
              className="absolute inset-0 w-full h-full opacity-25 pointer-events-none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#3b82f6" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#grid)" />
              {/* Equator & Prime Meridian */}
              <line
                x1="0"
                y1="50%"
                x2="100%"
                y2="50%"
                stroke="#3b82f6"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
              <line
                x1="50%"
                y1="0"
                x2="50%"
                y2="100%"
                stroke="#3b82f6"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
            </svg>

            {/* Connect hops with SVG lines */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
              {geoHops.slice(0, -1).map((hop, i) => {
                const p1 = toMapCoords(hop.latitude!, hop.longitude!);
                const p2 = toMapCoords(geoHops[i + 1].latitude!, geoHops[i + 1].longitude!);
                return (
                  <line
                    key={i}
                    x1={`${p1.x}%`}
                    y1={`${p1.y}%`}
                    x2={`${p2.x}%`}
                    y2={`${p2.y}%`}
                    stroke={hop.anomalous ? "#ef4444" : "#3b82f6"}
                    strokeWidth="2"
                    strokeDasharray="4 4"
                    className="animate-pulse"
                  />
                );
              })}
            </svg>

            {/* Hop Markers */}
            {geoHops.map((hop) => {
              const { x, y } = toMapCoords(hop.latitude!, hop.longitude!);
              return (
                <div
                  key={hop.hop_number}
                  className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer z-10"
                  style={{ left: `${x}%`, top: `${y}%` }}
                >
                  <div
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white shadow-lg border-2 transition-transform group-hover:scale-125 ${
                      hop.anomalous ? "bg-red-600 border-red-300" : "bg-blue-600 border-blue-300"
                    }`}
                  >
                    {hop.hop_number}
                  </div>

                  {/* Tooltip on hover */}
                  <div className="hidden group-hover:block absolute z-30 bottom-8 left-1/2 -translate-x-1/2 bg-slate-900 border border-slate-700 text-white rounded-lg p-3 text-xs font-mono whitespace-nowrap shadow-2xl space-y-1 min-w-[200px]">
                    <div className="font-bold text-blue-400 flex items-center justify-between">
                      <span>Hop #{hop.hop_number}</span>
                      <span className="text-[10px] text-slate-400">{hop.country}</span>
                    </div>
                    <div className="text-white font-semibold">{hop.ip}</div>
                    <div className="text-slate-300 text-[11px]">
                      {hop.city ? `${hop.city}, ` : ""}
                      {hop.region ? `${hop.region}, ` : ""}
                      {hop.country}
                    </div>
                    <div className="text-[10px] text-slate-400 truncate">
                      {hop.org || hop.isp || hop.asn || "Autonomous System"}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Lat: {hop.latitude?.toFixed(4)}, Lon: {hop.longitude?.toFixed(4)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-8 text-center space-y-2">
            <Globe className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs font-medium text-slate-300">
              No External Geolocation Coordinates Plotted
            </p>
            <p className="text-[11px] text-slate-500 max-w-md mx-auto">
              {hasUnconfiguredError
                ? "GeoLocation unavailable — IPinfo API key not configured. Private subnets are excluded and public IP coordinates are withheld to avoid synthetic data."
                : "All relay headers in this case are within private RFC 1918 subnets or lack external public IP coordinates."}
            </p>
          </div>
        )}

        {/* Detailed Hop-by-Hop Forensics Table / Grid */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Network className="w-4 h-4 text-blue-400" />
              Comprehensive Relay Hop Forensics & Geolocation Table
            </h4>
            <span className="text-[11px] font-mono text-slate-500">
              {hops.length} Relays Inspected
            </span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">
            <table className="w-full text-left text-xs font-mono min-w-[700px]">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-2.5 px-3">Hop #</th>
                  <th className="py-2.5 px-3">IP Address</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Location (City, Region, Country)</th>
                  <th className="py-2.5 px-3">Coordinates (Lat / Lon)</th>
                  <th className="py-2.5 px-3">ISP / Organization & ASN</th>
                  <th className="py-2.5 px-3">Timestamp / Delay</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {hops.map((hop) => (
                  <tr
                    key={hop.hop_number}
                    className={`hover:bg-slate-900/50 transition-colors ${
                      hop.anomalous ? "bg-red-950/10" : ""
                    }`}
                  >
                    {/* Hop # */}
                    <td className="py-2.5 px-3 font-bold text-blue-400">
                      #{hop.hop_number}
                    </td>

                    {/* IP */}
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-white">
                        {hop.ip || "No IP in Header"}
                      </div>
                      {hop.from_host && (
                        <div className="text-[10px] text-slate-400 truncate max-w-[140px]">
                          from {hop.from_host}
                        </div>
                      )}
                    </td>

                    {/* Type Badge */}
                    <td className="py-2.5 px-3">
                      {hop.is_private ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                          <Lock className="w-2.5 h-2.5" />
                          Private / Internal
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-950 text-blue-300 border border-blue-800">
                          <Globe className="w-2.5 h-2.5 text-blue-400" />
                          Public IP
                        </span>
                      )}
                    </td>

                    {/* Location */}
                    <td className="py-2.5 px-3">
                      {hop.is_private ? (
                        <span className="text-slate-500 italic">Internal Network Hop</span>
                      ) : hop.city || hop.country ? (
                        <div>
                          <span className="font-medium text-slate-100">
                            {hop.city ? `${hop.city}, ` : ""}
                            {hop.region ? `${hop.region}, ` : ""}
                            {hop.country}
                          </span>
                        </div>
                      ) : (
                        <span className="text-amber-400/80 text-[11px]">
                          {hop.geo_error || "GeoLocation unavailable"}
                        </span>
                      )}
                    </td>

                    {/* Coordinates */}
                    <td className="py-2.5 px-3 text-slate-400">
                      {hop.latitude !== null && hop.longitude !== null ? (
                        <span className="text-emerald-400 font-mono">
                          {hop.latitude.toFixed(4)}, {hop.longitude.toFixed(4)}
                        </span>
                      ) : (
                        <span className="text-slate-600">N/A</span>
                      )}
                    </td>

                    {/* ISP / Org & ASN */}
                    <td className="py-2.5 px-3 max-w-[200px]">
                      {hop.is_private ? (
                        <span className="text-slate-500">RFC 1918 / Loopback</span>
                      ) : hop.org || hop.isp || hop.asn ? (
                        <div className="truncate">
                          <div className="text-slate-200 truncate">
                            {hop.isp || hop.org || "Network Provider"}
                          </div>
                          {hop.asn && (
                            <div className="text-[10px] text-blue-400 truncate">
                              ASN: {hop.asn}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-500">Unresolved ASN</span>
                      )}
                    </td>

                    {/* Timestamp */}
                    <td className="py-2.5 px-3 text-[11px] text-slate-400">
                      {hop.timestamp ? (
                        <div>
                          <div>{new Date(hop.timestamp).toLocaleTimeString()}</div>
                          {hop.delay_seconds > 0 && (
                            <div className="text-[10px] text-slate-500">
                              +{hop.delay_seconds}s delay
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600">No timestamp</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
