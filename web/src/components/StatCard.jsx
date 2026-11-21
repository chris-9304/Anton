export default function StatCard({ label, value, accent = "text-blue-400" }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 min-w-0">
      <div className={`text-2xl font-bold ${accent}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}
