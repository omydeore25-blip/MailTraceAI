import React from "react";
import { ShieldCheck, Cpu, Terminal } from "lucide-react";

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-slate-850 bg-slate-950/60 mt-auto py-6 text-xs text-slate-500">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-blue-500" />
          <span><b>MailTrace AI</b> — Autonomous Threat Detection & Forensic Attribution Engine</span>
        </div>
        <div className="flex items-center gap-4 font-mono text-[11px] text-slate-400">
          <span className="flex items-center gap-1"><Cpu className="w-3.5 h-3.5 text-indigo-400" /> ML NLP & Heuristic Classifier</span>
          <span>•</span>
          <span className="flex items-center gap-1"><Terminal className="w-3.5 h-3.5 text-emerald-400" /> MITRE ATT&CK Matrix</span>
        </div>
      </div>
    </footer>
  );
};
