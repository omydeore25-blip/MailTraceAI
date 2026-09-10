import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, Activity, Network, Search, History, UploadCloud, Cpu } from "lucide-react";
import { apiClient } from "../../lib/api-client";
import { Badge } from "../ui/badge";

export const Navbar: React.FC = () => {
  const location = useLocation();
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    apiClient.getHealth().then(setHealth).catch(() => setHealth({ status: "offline" }));
  }, []);

  const navItems = [
    { label: "Dashboard", path: "/", icon: Activity },
    { label: "New Scan", path: "/scan", icon: UploadCloud },
    { label: "Infrastructure Graph", path: "/graph", icon: Network },
    { label: "Threat Intel", path: "/intel", icon: Search },
    { label: "Scan History", path: "/history", icon: History },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <Link to="/" className="flex items-center gap-3 group">
          <div className="p-2 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-tight text-white">MailTrace</span>
              <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">AI</span>
            </div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">SIH 2026 Platform</p>
          </div>
        </Link>

        {/* Navigation */}
        <nav className="hidden md:flex items-center gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? "bg-blue-600/10 text-blue-400 border border-blue-500/30"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Engine Status */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-slate-300 font-mono text-[11px]">
              {health?.graph_engine?.mode === "neo4j_native" ? "Neo4j Active" : "Adaptive Fallback Engine"}
            </span>
          </div>

          <Link
            to="/scan"
            className="flex items-center gap-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-2 rounded-lg transition-colors shadow-lg shadow-blue-600/20"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Analyze Email</span>
          </Link>
        </div>
      </div>
    </header>
  );
};
