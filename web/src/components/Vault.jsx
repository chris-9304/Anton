// Explicit stub: the README marks Vault as "coming soon" and it isn't implemented
// anywhere in the backend (no /api/vault/* routes exist). Do not fake functionality
// here -- this matches the Slint desktop app, which also has no Vault tab yet.
export default function Vault() {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Vault</h2>
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-slate-500">
        Protected files management — coming soon.
      </div>
    </div>
  );
}
