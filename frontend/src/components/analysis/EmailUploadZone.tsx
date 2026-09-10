import React, { useState, useRef } from "react";
import { UploadCloud, FileText, Sparkles, AlertCircle, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "../ui/button";
import { apiClient } from "../../lib/api-client";
import { EmailAnalysisDetail } from "../../types";

interface EmailUploadZoneProps {
  onAnalysisComplete: (data: EmailAnalysisDetail) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export const EmailUploadZone: React.FC<EmailUploadZoneProps> = ({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
}) => {
  const [activeTab, setActiveTab] = useState<"upload" | "paste">("upload");
  const [rawText, setRawText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (file: File) => {
    setError(null);
    setIsLoading(true);
    try {
      const data = await apiClient.uploadEmail(file);
      onAnalysisComplete(data);
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to parse email file. Please verify file format.");
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!rawText.trim()) {
      setError("Please paste raw email headers or RFC MIME message.");
      return;
    }
    setError(null);
    setIsLoading(true);
    try {
      const data = await apiClient.pasteEmail(rawText);
      onAnalysisComplete(data);
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to analyze raw email text.");
    } finally {
      setIsLoading(false);
    }
  };

  const loadSample = async (sampleType: string) => {
    setError(null);
    setIsLoading(true);
    try {
      let sampleRaw = "";
      if (sampleType === "clean") {
        sampleRaw = `Received: from mail-relay.techweekly.org (mail-relay.techweekly.org [198.51.100.25])
	by mx.google.com with ESMTPS id a12-v6.32
	for <analyst@mailtrace.ai>; Fri, 04 Sep 2026 08:30:00 +0000 (UTC)
Authentication-Results: mx.google.com;
	dkim=pass header.i=@techweekly.org;
	spf=pass (google.com: domain of newsletter@techweekly.org designates 198.51.100.25 as permitted sender);
	dmarc=pass (p=REJECT) header.from=techweekly.org
From: "Tech Weekly Digest" <newsletter@techweekly.org>
To: analyst@mailtrace.ai
Subject: Tech Weekly Issue #142: Breakthroughs in Autonomous AI & Cybersecurity
Date: Fri, 04 Sep 2026 08:29:30 +0000
Content-Type: text/plain

Welcome to Tech Weekly! Visit our main research link: https://techweekly.org/stories/issue-142 for the full brief.`;
      } else if (sampleType === "phishing") {
        sampleRaw = `Received: from relay02.bulletproof-mail.ru ([194.26.29.112])
	by mx.company-defense.com with ESMTP id m449912
	for <cfo@victim-corp.com>; Fri, 04 Sep 2026 09:12:00 +0000
Authentication-Results: mx.company-defense.com;
	dkim=fail reason="signature missing";
	spf=fail (company-defense.com: domain of admin@microsoft.com does not designate 194.26.29.112 as permitted sender);
	dmarc=fail (p=REJECT) header.from=microsoft.com
From: "Microsoft 365 Security Alert" <admin@microsoft.com>
Reply-To: security-team@micros0ft-security-auth.com
Return-Path: <bounce@bulletproof-mail.ru>
To: cfo@victim-corp.com
Subject: [CRITICAL ALERT] Immediate Action Required: Unauthorized Sign-In Detected on your Microsoft Account
Date: Fri, 04 Sep 2026 09:11:00 +0000
Content-Type: text/html

Your Microsoft 365 session has expired. Action required within 24 hours to prevent account suspension.
Verify now at: https://micros0ft-security-auth.com/login/verify-account?token=987213`;
      } else if (sampleType === "bec") {
        sampleRaw = `Received: from outbound.freemail-secure.com (outbound.freemail-secure.com [203.0.113.88])
	by mx.victim-corp.com with ESMTPS id b552109
	for <controller@victim-corp.com>; Fri, 04 Sep 2026 10:05:00 +0000
Authentication-Results: mx.victim-corp.com; dkim=pass; spf=pass; dmarc=none
From: "Robert Smith - Chief Executive Officer" <ceo-private-exec@freemail-secure.com>
Reply-To: exec-reply-desk@payroll-portal-update.org
To: controller@victim-corp.com
Subject: Strictly Confidential: Urgent Wire Transfer Request for Q3 Strategic Acquisition
Date: Fri, 04 Sep 2026 10:04:15 +0000
Content-Type: text/plain

Controller,
We require an immediate wire transfer of $84,500 to our strategic escrow account before 1:00 PM EST.
Routing and swift code: CUSTUS33XXX. Send confirmation to exec-reply-desk@payroll-portal-update.org. Do not discuss.`;
      } else if (sampleType === "spoofed") {
        sampleRaw = `Received: from fake-gateway.badactor.net ([185.220.101.5])
	by mx.receiver-inbox.com with ESMTP id sp991823; Fri, 04 Sep 2026 11:30:00 +0000
Received: from forged-host ([192.168.1.50]); Fri, 04 Sep 2026 11:45:00 +0000
Authentication-Results: mx.receiver-inbox.com; spf=fail; dkim=fail; dmarc=fail (p=REJECT)
From: "PayPal Security" <service@paypal.com>
Reply-To: claims@paypal-dispute-resolution.xyz
Subject: [Urgent Notification] Unauthorized Payment of $649.99 Sent from Your PayPal Account
Date: Fri, 04 Sep 2026 11:29:00 +0000
Content-Type: text/plain

You sent $649.99 to CryptoExchange. Cancel transaction immediately: http://paypal-dispute-resolution.xyz/auth/cancel`;
      }

      const data = await apiClient.pasteEmail(sampleRaw);
      onAnalysisComplete(data);
    } catch (err: any) {
      setError("Failed to load sample analysis.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Tab Switcher */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex gap-2">
          <button
            onClick={() => setActiveTab("upload")}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "upload"
                ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            Upload File (.eml / .msg)
          </button>
          <button
            onClick={() => setActiveTab("paste")}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "paste"
                ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="w-4 h-4" />
            Paste Raw MIME / Headers
          </button>
        </div>

        {/* Quick Sample Selector */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" /> Presets:
          </span>
          <button
            onClick={() => loadSample("clean")}
            disabled={isLoading}
            className="text-[11px] px-2.5 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 hover:bg-emerald-900/60 transition-colors"
          >
            Clean Email
          </button>
          <button
            onClick={() => loadSample("phishing")}
            disabled={isLoading}
            className="text-[11px] px-2.5 py-1 rounded bg-red-950/60 text-red-400 border border-red-800/60 hover:bg-red-900/60 transition-colors"
          >
            Credential Phish
          </button>
          <button
            onClick={() => loadSample("bec")}
            disabled={isLoading}
            className="text-[11px] px-2.5 py-1 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60 hover:bg-amber-900/60 transition-colors"
          >
            VIP BEC Fraud
          </button>
          <button
            onClick={() => loadSample("spoofed")}
            disabled={isLoading}
            className="text-[11px] px-2.5 py-1 rounded bg-purple-950/60 text-purple-400 border border-purple-800/60 hover:bg-purple-900/60 transition-colors"
          >
            Spoofed Transit
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 p-3.5 rounded-lg bg-red-950/50 border border-red-800/60 text-red-300 text-xs">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Upload Box */}
      {activeTab === "upload" ? (
        <div
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-800 hover:border-blue-500/60 bg-slate-900/40 hover:bg-slate-900/70 rounded-2xl p-10 text-center transition-all cursor-pointer group"
        >
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept=".eml,.msg,message/rfc822"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFileUpload(file);
            }}
          />
          <div className="w-16 h-16 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
            {isLoading ? <Loader2 className="w-8 h-8 animate-spin" /> : <UploadCloud className="w-8 h-8" />}
          </div>
          <h4 className="text-base font-semibold text-white mb-1">
            {isLoading ? "Executing Deep Forensic Inspection..." : "Drop suspicious email here or click to browse"}
          </h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Supports RFC 822/5322 compliant <span className="font-mono text-blue-400">.eml</span> files, Outlook <span className="font-mono text-blue-400">.msg</span> binaries, and multi-part messages.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <textarea
            rows={10}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste raw email message with headers (Received, From, To, Subject, etc.) and body here..."
            className="w-full font-mono text-xs bg-slate-900/80 border border-slate-800 rounded-xl p-4 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <div className="flex justify-end">
            <Button onClick={handlePasteSubmit} disabled={isLoading} className="gap-2">
              {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
              <span>Inspect Raw Stream</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
