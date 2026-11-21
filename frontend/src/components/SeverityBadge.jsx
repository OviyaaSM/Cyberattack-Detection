import React from 'react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: 'bg-red-950/80',
    border: 'border-red-500/50',
    text: 'text-red-400',
    dot: 'bg-red-500',
  },
  HIGH: {
    bg: 'bg-orange-950/80',
    border: 'border-orange-500/50',
    text: 'text-orange-400',
    dot: 'bg-orange-500',
  },
  MEDIUM: {
    bg: 'bg-amber-950/80',
    border: 'border-amber-500/50',
    text: 'text-amber-400',
    dot: 'bg-amber-500',
  },
  LOW: {
    bg: 'bg-emerald-950/80',
    border: 'border-emerald-500/50',
    text: 'text-emerald-400',
    dot: 'bg-emerald-500',
  },
};

export default function SeverityBadge({ severity = 'LOW', size = 'sm' }) {
  const sevKey = (severity || 'LOW').toUpperCase();
  const config = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.LOW;

  const sizeClasses = size === 'lg'
    ? 'px-3 py-1 text-sm'
    : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium rounded-full border ${config.bg} ${config.border} ${config.text} ${sizeClasses}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot} animate-pulse`} />
      {sevKey}
    </span>
  );
}
