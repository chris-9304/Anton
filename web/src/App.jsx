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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col md:flex-row">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-10 focus:bg-blue-600 focus:p-3"
      >
        Skip to content
      </a>
      <aside className="md:w-52 md:shrink-0 border-b md:border-b-0 md:border-r border-slate-800 p-4 flex flex-col">
        <div className="mb-4 md:mb-6">
          <h1 className="text-xl font-extrabold tracking-wide">ANTON</h1>
          <p className="text-xs text-slate-400">Anti-Ransomware</p>
        </div>
        <nav
          aria-label="Main navigation"
          className="flex md:flex-col gap-1 overflow-x-auto pb-1"
        >
          {TABS.map((tab) => (
            <button
              key={tab}
              aria-current={activeTab === tab ? "page" : undefined}
              onClick={() => setActiveTab(tab)}
              className={`shrink-0 text-left px-3 py-2 rounded-lg text-sm transition-colors ${
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

      <main
        id="main-content"
        tabIndex={-1}
        className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8"
      >
        {activeTab === "Dashboard" && <Dashboard />}
        {activeTab === "Scan Activity" && <ScanActivity />}
        {activeTab === "History" && <History />}
        {activeTab === "Settings" && <Settings />}
        {activeTab === "Vault" && <Vault />}
      </main>
    </div>
  );
}
