import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

export function getThreatColor(threatLevel: string) {
  switch (threatLevel?.toLowerCase()) {
    case "critical":
      return "text-red-500 bg-red-500/10 border-red-500/20";
    case "malicious":
      return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    case "suspicious":
      return "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
    case "clean":
    default:
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  }
}
