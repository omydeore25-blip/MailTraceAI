import React from "react";
import { BrainCircuit, Zap, Eye, CheckCircle2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface AIInsightCardProps {
  insights: Record<string, any>;
}

export const AIInsightCard: React.FC<AIInsightCardProps> = ({ insights }) => {
  if (!insights) return null;

  const category = insights.primary_category || "Clean / Benign";
  const confidence = (insights.confidence || 0.85) * 100;
  const explanation = insights.explanation || "No deceptive intent detected.";
  const levers: string[] = insights.psychological_levers || [];
  const heuristics = insights.linguistic_heuristics || {};
  const triggers: string[] = heuristics.triggered_patterns || [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <BrainCircuit className="w-4 h-4 text-purple-400" />
          AI & NLP Intent Analysis (Social Engineering Detection)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Category & Confidence */}
        <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Classified Intent:</span>
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <span>{category}</span>
            </h4>
          </div>
          <div className="text-right">
            <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Model Confidence:</span>
            <span className="text-xs font-mono font-bold text-purple-400">{confidence.toFixed(1)}%</span>
          </div>
        </div>

        {/* Narrative Explanation */}
        <div className="text-xs text-slate-300 bg-slate-900/40 border border-slate-850 rounded-lg p-3 leading-relaxed">
          {explanation}
        </div>

        {/* Psychological Levers */}
        {levers.length > 0 && (
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">Psychological Levers Identified:</span>
            <div className="flex flex-wrap gap-2">
              {levers.map((lever, idx) => (
                <Badge key={idx} variant="warning" className="gap-1 text-[11px]">
                  <Zap className="w-3 h-3" /> {lever}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Extracted Pattern Triggers */}
        {triggers.length > 0 && (
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">Linguistic Triggers Flagged:</span>
            <div className="space-y-1.5">
              {triggers.map((trigger, idx) => (
                <div key={idx} className="text-xs font-mono text-slate-300 bg-slate-950/70 border border-slate-850 px-2.5 py-1.5 rounded flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                  <span>{trigger}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
