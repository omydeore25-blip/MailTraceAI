import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Navbar } from "./components/layout/Navbar";
import { Footer } from "./components/layout/Footer";
import { DashboardPage } from "./pages/DashboardPage";
import { NewScanPage } from "./pages/NewScanPage";
import { AnalysisDetailPage } from "./pages/AnalysisDetailPage";
import { InfrastructureGraphPage } from "./pages/InfrastructureGraphPage";
import { ThreatIntelLookupPage } from "./pages/ThreatIntelLookupPage";
import { HistoryPage } from "./pages/HistoryPage";

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan" element={<NewScanPage />} />
            <Route path="/analysis/:id" element={<AnalysisDetailPage />} />
            <Route path="/graph" element={<InfrastructureGraphPage />} />
            <Route path="/intel" element={<ThreatIntelLookupPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
};

export default App;
