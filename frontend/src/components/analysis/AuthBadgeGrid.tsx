import React from "react";
import { CheckCircle2, XCircle, AlertCircle, ShieldCheck, HelpCircle } from "lucide-react";
import { AuthSummary } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface AuthBadgeGridProps {
  auth: AuthSummary | null;
}

export const AuthBadgeGrid: React.FC<AuthBadgeGridProps> = ({ auth }) => {
  if (!auth) return null;

  const renderStatus = (status: string) => {
    const s = status.toLowerCase();
    if (s === "pass") {
      return (
        <Badge variant="success" className="gap-1">
          <CheckCircle2 className="w-3 h-3" /> PASS
        </Badge>
      );
    } else if (s === "fail" || s === "reject" || s === "invalid") {
      return (
        <Badge variant="destructive" className="gap-1">
          <XCircle className="w-3 h-3" /> {status.toUpperCase()}
        </Badge>
      );
    } else if (s === "softfail" || s === "quarantine") {
      return (
        <Badge variant="warning" className="gap-1">
          <AlertCircle className="w-3 h-3" /> {status.toUpperCase()}
        </Badge>
      );
    } else {
      return (
        <Badge variant="secondary" className="gap-1">
          <HelpCircle className="w-3 h-3" /> {status.toUpperCase()}
        </Badge>
      );
    }
  };

  const protocols = [
    {
      name: "SPF (RFC 7208)",
      sub: "Sender Policy Framework",
      status: auth.spf.status,
      aligned: auth.spf.aligned,
      target: auth.spf.evaluated_domain || "N/A",
      details: auth.spf.details || "No record",
    },
    {
      name: "DKIM (RFC 6376)",
      sub: "Cryptographic Signature",
      status: auth.dkim.status,
      aligned: auth.dkim.aligned,
      target: auth.dkim.domain ? `d=${auth.dkim.domain} s=${auth.dkim.selector || "default"}` : "No Signature",
      details: auth.dkim.details || "No signature",
    },
    {
      name: "DMARC (RFC 7489)",
      sub: "Domain-based Alignment",
      status: auth.dmarc.status,
      aligned: auth.dmarc.spf_aligned || auth.dmarc.dkim_aligned,
      target: `Policy: p=${auth.dmarc.policy || "none"}`,
      details: auth.dmarc.details || "No evaluation",
    },
    {
      name: "ARC (RFC 8617)",
      sub: "Authenticated Received Chain",
      status: auth.arc.status,
      aligned: auth.arc.chain_validated,
      target: auth.arc.chain_validated ? "Chain Validated" : "Direct Transit",
      details: auth.arc.details || "Direct transit",
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          Email Authentication Protocols (SPF / DKIM / DMARC / ARC)
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {protocols.map((proto) => (
            <div
              key={proto.name}
              className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-xs text-white">{proto.name}</span>
                  {renderStatus(proto.status)}
                </div>
                <div className="text-[10px] text-slate-400 font-mono mb-2">{proto.target}</div>
                <p className="text-[11px] text-slate-300 line-clamp-2 leading-relaxed">{proto.details}</p>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-850 flex items-center justify-between text-[10px]">
                <span className="text-slate-400">Alignment:</span>
                <span className={proto.aligned ? "text-emerald-400 font-semibold" : "text-amber-400 font-semibold"}>
                  {proto.aligned ? "Aligned" : "Unaligned / Missing"}
                </span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
