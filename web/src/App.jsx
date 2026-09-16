import { useState } from "react";
import Dashboard from "./components/Dashboard.jsx";
import ScanActivity from "./components/ScanActivity.jsx";
import History from "./components/History.jsx";
import Settings from "./components/Settings.jsx";
import Vault from "./components/Vault.jsx";

const TABS = ["Dashboard", "Scan Activity", "History", "Settings", "Vault"];

export default function App() {
  const [activeTab, setActiveTab] = useState("Dashboard");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <aside className="w-52 border-r border-slate-800 p-4 flex flex-col">
        <div className="mb-6">
          <h1 className="text-xl font-extrabold tracking-wide">ANTON</h1>
          <p className="text-xs text-slate-400">Anti-Ransomware</p>
        </div>
        <nav className="flex flex-col gap-1">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                activeTab === tab
                  ? "bg-blue-600 text-white font-semibold"
                  : "text-slate-300 hover:bg-slate-800"
              }`}
            >
              {tab}
            </button>
          ))}
        </nav>
      </aside>

      <main className="flex-1 p-8 overflow-y-auto">
        {activeTab === "Dashboard" && <Dashboard />}
        {activeTab === "Scan Activity" && <ScanActivity />}
        {activeTab === "History" && <History />}
        {activeTab === "Settings" && <Settings />}
        {activeTab === "Vault" && <Vault />}
      </main>
    </div>
  );
}
