export default function StatCard({ label, value, accent = "text-blue-400" }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex-1">
      <div className={`text-2xl font-bold ${accent}`}>{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}
