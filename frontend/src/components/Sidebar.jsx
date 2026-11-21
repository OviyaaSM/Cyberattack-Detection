import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Clock,
  Share2,
  FlaskConical,
  FileSearch,
  Settings,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/events', label: 'Live Monitor', icon: Activity },
  { path: '/detection', label: 'Attack Detection', icon: ShieldAlert },
  { path: '/timeline', label: 'Temporal Timeline', icon: Clock },
  { path: '/network', label: 'Network Graph', icon: Share2 },
  { path: '/simulation', label: 'Simulation Lab', icon: FlaskConical },
  { path: '/investigation', label: 'Investigation Center', icon: FileSearch },
  { path: '/settings', label: 'Reports & Config', icon: Settings },
];

export default function Sidebar() {
  return (
    <aside className="w-64 flex-shrink-0 border-r border-slate-800 bg-slate-950/95 flex flex-col justify-between p-4">
      <div className="space-y-6">
        <div>
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 font-mono">
            Navigation Menu
          </span>
          <nav className="mt-2 space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-mono transition-all ${
                      isActive
                        ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 shadow-sm shadow-cyan-950/50 font-semibold'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 border border-transparent'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* SOC Engine Info Badge */}
        <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-900/60 text-[11px] font-mono text-slate-400 space-y-1.5">
          <div className="flex items-center justify-between text-slate-300 font-semibold">
            <span>Reasoning Core</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Temporal Interval Algebra & Cross-Host Correlation Active
          </p>
        </div>
      </div>

      {/* Footer Info */}
      <div className="pt-4 border-t border-slate-800 text-[10px] text-slate-500 font-mono">
        <p>Cyberattack Detection Platform</p>
        <p className="text-slate-600">Deep Temporal Analysis Engine</p>
      </div>
    </aside>
  );
}
