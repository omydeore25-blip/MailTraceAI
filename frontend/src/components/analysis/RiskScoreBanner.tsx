import React from "react";
import { ShieldAlert, ShieldCheck, ShieldX, AlertTriangle, CheckCircle, ArrowRight } from "lucide-react";
import { RiskScoreResult } from "../../types";
import { Card, CardContent } from "../ui/card";
import { Progress } from "../ui/progress";

interface RiskScoreBannerProps {
  assessment: RiskScoreResult | null;
}

export const RiskScoreBanner: React.FC<RiskScoreBannerProps> = ({ assessment }) => {
  if (!assessment) return null;

  const score = assessment.overall_score;
  const level = assessment.threat_level;

  let bgGradient = "from-emerald-950/40 to-slate-900/40 border-emerald-500/30";
  let scoreColor = "text-emerald-400";
  let Icon = ShieldCheck;

  if (level === "Critical") {
    bgGradient = "from-red-950/40 to-slate-900/40 border-red-500/40";
    scoreColor = "text-red-400";
    Icon = ShieldAlert;
  } else if (level === "Malicious") {
    bgGradient = "from-orange-950/40 to-slate-900/40 border-orange-500/40";
    scoreColor = "text-orange-400";
    Icon = ShieldX;
  } else if (level === "Suspicious") {
    bgGradient = "from-amber-950/40 to-slate-900/40 border-amber-500/30";
    scoreColor = "text-amber-400";
    Icon = AlertTriangle;
  }

  return (
    <Card className={`border ${bgGradient}`}>
      <CardContent className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Main Risk Gauge */}
          <div className="lg:col-span-4 flex items-center gap-5 border-b lg:border-b-0 lg:border-r border-slate-800 pb-5 lg:pb-0 lg:pr-6">
            <div className="relative flex items-center justify-center shrink-0">
              <div className="w-24 h-24 rounded-full border-4 border-slate-800 flex flex-col items-center justify-center bg-slate-950/80 shadow-2xl">
                <span className={`text-3xl font-black font-mono tracking-tight ${scoreColor}`}>
                  {score.toFixed(0)}
                </span>
                <span className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">/ 100</span>
              </div>
            </div>

            <div>
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`w-5 h-5 ${scoreColor}`} />
                <h3 className={`text-xl font-bold tracking-tight ${scoreColor}`}>{level} Threat</h3>
              </div>
              <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">{assessment.summary}</p>
            </div>
          </div>

          {/* Action Recommendation */}
          <div className="lg:col-span-3 border-b lg:border-b-0 lg:border-r border-slate-800 pb-5 lg:pb-0 lg:pr-6">
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5 text-blue-400" /> Recommended Action
            </div>
            <div className="text-xs font-semibold text-slate-200 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
              {assessment.recommended_action}
            </div>
          </div>

          {/* 5-Factor Weighted Contribution */}
          <div className="lg:col-span-5 space-y-2">
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2">
              Explainable Risk Breakdown
            </div>
            {assessment.factors.map((factor) => (
              <div key={factor.category} className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-300 font-medium">{factor.category} ({factor.weight_percentage}%)</span>
                  <span className="font-mono text-slate-400">+{factor.weighted_contribution.toFixed(1)} pts</span>
                </div>
                <Progress
                  value={factor.score}
                  className="h-1.5"
                  indicatorClassName={factor.score > 50 ? "bg-red-500" : factor.score > 20 ? "bg-amber-500" : "bg-emerald-500"}
                />
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
