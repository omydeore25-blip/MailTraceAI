import React, { useState, useEffect } from "react";
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ShieldAlert,
  Globe,
  Link as LinkIcon,
  Mail,
  User,
  HardDrive,
  Info,
  MapPin,
  Fingerprint,
  Target,
  Crosshair,
  AlertOctagon,
  Layers,
  ArrowRight,
} from "lucide-react";
import { GraphData, GraphNode, GraphEdge } from "../../types";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/card";
import { Badge } from "../ui/badge";

interface ThreatGraphCanvasProps {
  graphData: GraphData | null;
}

export const ThreatGraphCanvas: React.FC<ThreatGraphCanvasProps> = ({ graphData }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeCategory, setActiveCategory] = useState<string>("ALL");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (graphData && graphData.nodes.length > 0) {
      setSelectedNode(graphData.nodes[0]);
    }
  }, [graphData]);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <Card className="border border-slate-800">
        <CardContent className="p-12 text-center text-slate-400 text-xs">
          No graph entities generated for this case.
        </CardContent>
      </Card>
    );
  }

  const getNodeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "email":
        return <Mail className="w-4 h-4 text-blue-400" />;
      case "address":
      case "sender":
        return <User className="w-4 h-4 text-emerald-400" />;
      case "domain":
        return <HardDrive className="w-4 h-4 text-indigo-400" />;
      case "ip":
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case "url":
        return <LinkIcon className="w-4 h-4 text-amber-400" />;
      case "hash":
        return <Fingerprint className="w-4 h-4 text-purple-400" />;
      case "location":
        return <MapPin className="w-4 h-4 text-teal-400" />;
      case "threat_actor":
      case "actor":
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case "campaign":
        return <Target className="w-4 h-4 text-rose-400" />;
      case "mitre_technique":
      case "mitre":
        return <Crosshair className="w-4 h-4 text-orange-400" />;
      case "threat_intel":
        return <AlertOctagon className="w-4 h-4 text-red-500" />;
      default:
        return <Network className="w-4 h-4 text-slate-400" />;
    }
  };

  const getNodeBorder = (threat: string) => {
    switch (threat?.toLowerCase()) {
      case "critical":
      case "malicious":
        return "border-red-500/80 bg-red-950/70 text-red-300 shadow-red-900/30";
      case "suspicious":
        return "border-amber-500/80 bg-amber-950/70 text-amber-300 shadow-amber-900/30";
      case "clean":
      default:
        return "border-blue-500/60 bg-blue-950/60 text-blue-300 shadow-blue-900/20";
    }
  };

  const filteredNodes =
    activeCategory === "ALL"
      ? graphData.nodes
      : graphData.nodes.filter((n) => {
          if (activeCategory === "INFRASTRUCTURE") {
            return ["ip", "domain", "location"].includes(n.type.toLowerCase());
          }
          if (activeCategory === "IOCS") {
            return ["url", "hash", "threat_intel"].includes(n.type.toLowerCase());
          }
          if (activeCategory === "ATTRIBUTION") {
            return ["threat_actor", "campaign", "mitre_technique"].includes(n.type.toLowerCase());
          }
          return true;
        });

  return (
    <Card className="overflow-hidden border border-slate-800">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <CardTitle className="text-base sm:text-lg flex items-center gap-2 text-white">
              Adversarial Threat & Infrastructure Graph
              <Badge variant="outline" className="text-xs font-mono">
                {graphData.total_nodes} Nodes / {graphData.total_edges} Edges
              </Badge>
            </CardTitle>
            <p className="text-xs text-slate-400">
              Interactive relationship topology correlating email origin, transit hops, IOCs, and ATT&CK techniques.
            </p>
          </div>
        </div>

        {/* View Controls & Filter */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Categories */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
            {["ALL", "INFRASTRUCTURE", "IOCS", "ATTRIBUTION"].map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  activeCategory === cat ? "bg-blue-600 text-white" : "text-slate-400 hover:text-white"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => setZoom((z) => Math.min(1.8, z + 0.1))}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.6, z - 0.1))}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0 grid grid-cols-1 lg:grid-cols-12 min-h-[480px]">
        {/* Interactive Graph Canvas */}
        <div className="lg:col-span-8 bg-slate-950 p-6 relative overflow-hidden border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col justify-center items-center select-none">
          {/* Grid Background */}
          <div
            className="absolute inset-0 opacity-15"
            style={{
              backgroundImage: "radial-gradient(#3b82f6 1px, transparent 1px)",
              backgroundSize: "24px 24px",
            }}
          />

          <div
            className="relative transition-transform duration-200 ease-out flex flex-wrap gap-3.5 items-center justify-center max-w-2xl z-10"
            style={{ transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)` }}
          >
            {filteredNodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`cursor-pointer rounded-xl border-2 p-3 shadow-lg transition-all duration-200 flex items-center gap-2.5 max-w-xs ${getNodeBorder(
                    node.threat_level
                  )} ${isSelected ? "ring-2 ring-white scale-105" : "hover:scale-102 opacity-90 hover:opacity-100"}`}
                >
                  <div className="p-1.5 rounded-lg bg-slate-900/80 shrink-0">
                    {getNodeIcon(node.type)}
                  </div>
                  <div className="overflow-hidden">
                    <span className="text-[9px] uppercase font-mono tracking-wider opacity-70 block">
                      {node.type.replace("_", " ")}
                    </span>
                    <span className="text-xs font-semibold text-white truncate block max-w-[150px]">
                      {node.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Canvas helper badge */}
          <div className="absolute bottom-3 left-3 text-[10px] font-mono text-slate-400 bg-slate-900/80 px-2.5 py-1 rounded-md border border-slate-800">
            Click any entity node to inspect forensic attributes & relationships
          </div>
        </div>

        {/* Node Details Inspector Sidebar */}
        <div className="lg:col-span-4 bg-slate-900/40 p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Info className="w-4 h-4 text-blue-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-white">
                Entity Intelligence Inspector
              </h4>
            </div>

            {selectedNode ? (
              <div className="space-y-3.5">
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                    Entity Identifier / Label:
                  </span>
                  <div className="text-xs font-semibold text-white font-mono break-all bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                    {selectedNode.label}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] font-mono uppercase text-slate-400 block">
                      Node Class:
                    </span>
                    <span className="font-semibold text-slate-200 capitalize">
                      {selectedNode.type.replace("_", " ")}
                    </span>
                  </div>
                  <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] font-mono uppercase text-slate-400 block">
                      Threat Status:
                    </span>
                    <span
                      className={`font-semibold uppercase text-[11px] ${
                        selectedNode.threat_level === "critical" ||
                        selectedNode.threat_level === "malicious"
                          ? "text-red-400"
                          : selectedNode.threat_level === "suspicious"
                          ? "text-amber-400"
                          : "text-blue-400"
                      }`}
                    >
                      {selectedNode.threat_level}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                    Node Metadata & Attributes:
                  </span>
                  <pre className="p-3 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-300 border border-slate-800 max-h-44 overflow-y-auto leading-relaxed">
                    {JSON.stringify(selectedNode.details, null, 2)}
                  </pre>
                </div>

                {/* Connected Relationships */}
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1.5">
                    Connected Relationships (
                    {
                      graphData.edges.filter(
                        (e) => e.source === selectedNode.id || e.target === selectedNode.id
                      ).length
                    }
                    ):
                  </span>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto">
                    {graphData.edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((edge) => (
                        <div
                          key={edge.id}
                          className="text-[11px] font-mono bg-slate-950 px-2.5 py-1.5 rounded-md border border-slate-800 flex items-center justify-between text-slate-300"
                        >
                          <span className="text-blue-400 font-semibold">{edge.label}</span>
                          <span className="text-[10px] text-slate-500 truncate max-w-[140px]">
                            {edge.source === selectedNode.id ? `-> ${edge.target}` : `<- ${edge.source}`}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 text-center py-8">
                Select any node from the canvas to view detailed attributes.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>Graph Engine: {graphData.source_engine}</span>
            <span>Deterministic Layout</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
