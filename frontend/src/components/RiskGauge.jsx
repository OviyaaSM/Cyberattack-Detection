import React from 'react';

export default function RiskGauge({ score = 0, showDetails = true }) {
  const normalized = Math.min(Math.max(score, 0), 100);

  let color = 'text-emerald-400';
  let barColor = 'bg-emerald-500';
  let label = 'Low Risk';

  if (normalized >= 90) {
    color = 'text-red-500';
    barColor = 'bg-red-500';
    label = 'Critical Risk';
  } else if (normalized >= 70) {
    color = 'text-orange-400';
    barColor = 'bg-orange-500';
    label = 'High Risk';
  } else if (normalized >= 40) {
    color = 'text-amber-400';
    barColor = 'bg-amber-500';
    label = 'Medium Risk';
  }

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-slate-400 font-mono">Risk Index</span>
        <span className={`text-sm font-bold font-mono ${color}`}>
          {normalized.toFixed(1)}/100
        </span>
      </div>
      <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden border border-slate-700">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${normalized}%` }}
        />
      </div>
      {showDetails && (
        <div className="flex justify-between items-center mt-1 text-[10px] text-slate-500">
          <span>0 (Benign)</span>
          <span className={`font-medium ${color}`}>{label}</span>
          <span>100 (Critical)</span>
        </div>
      )}
    </div>
  );
}
