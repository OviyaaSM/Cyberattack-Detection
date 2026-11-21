import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan', alert = false }) {
  const colorMap = {
    cyan: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20',
    blue: 'border-blue-500/30 text-blue-400 bg-blue-950/20',
    red: 'border-red-500/40 text-red-400 bg-red-950/30',
    amber: 'border-amber-500/30 text-amber-400 bg-amber-950/20',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20',
  };

  const activeColor = colorMap[color] || colorMap.cyan;

  return (
    <div className={`p-4 rounded-xl border bg-slate-900/90 shadow-lg backdrop-blur-md transition-all hover:border-slate-600 ${alert ? 'border-red-500/60 ring-1 ring-red-500/30' : 'border-slate-800'}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <h3 className="text-2xl font-bold font-mono text-slate-100 mt-1">{value}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg border ${activeColor}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
    </div>
  );
}
