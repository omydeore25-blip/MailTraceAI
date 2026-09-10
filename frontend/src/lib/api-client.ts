import axios from "axios";
import { EmailAnalysisDetail, EmailAnalysisOverview, GraphData } from "../types";

const api = axios.create({
  baseURL: "/api/v1",
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("mailtrace_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const apiClient = {
  // Scans & Analysis
  async uploadEmail(file: File): Promise<EmailAnalysisDetail> {
    const formData = new FormData();
    formData.append("file", file);
    const res = await api.post<EmailAnalysisDetail>("/analysis/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return res.data;
  },

  async pasteEmail(rawText: string): Promise<EmailAnalysisDetail> {
    const res = await api.post<EmailAnalysisDetail>("/analysis/paste", {
      raw_email_text: rawText,
    });
    return res.data;
  },

  async getRecentScans(limit = 50): Promise<EmailAnalysisOverview[]> {
    const res = await api.get<EmailAnalysisOverview[]>("/analysis/", {
      params: { limit },
    });
    return res.data;
  },

  async getAnalysis(id: string): Promise<EmailAnalysisDetail> {
    const res = await api.get<EmailAnalysisDetail>(`/analysis/${id}`);
    return res.data;
  },

  async deleteAnalysis(id: string): Promise<{ status: string; id: string }> {
    const res = await api.delete<{ status: string; id: string }>(`/analysis/${id}`);
    return res.data;
  },


  // Graph
  async getGraph(analysisId: string): Promise<GraphData> {
    const res = await api.get<GraphData>(`/graph/analysis/${analysisId}`);
    return res.data;
  },

  // Threat Intel Lookup
  async lookupIOC(iocType: string, value: string) {
    const res = await api.get("/threat-intel/lookup", {
      params: { ioc_type: iocType, value },
    });
    return res.data;
  },

  // Health
  async getHealth() {
    const res = await api.get("/health");
    return res.data;
  },

  // Reports
  getPdfUrl(id: string): string {
    return `/api/v1/reports/${id}/pdf`;
  },

  getJsonUrl(id: string): string {
    return `/api/v1/reports/${id}/json`;
  },
};
