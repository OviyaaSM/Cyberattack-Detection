import React, { useState } from 'react';
import { Shield, Play, RotateCcw, AlertTriangle, CheckCircle2, Activity } from 'lucide-react';
import { api } from '../api/client';

export default function Navbar({ onRefresh, systemHealth = 'NORMAL' }) {
  const [isRunning, setIsRunning] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [msg, setMsg] = useState(null);

  const handleRunDetection = async () => {
    setIsRunning(true);
    try {
      const res = await api.runDetection();
      setMsg(`Detection complete: ${res.data.alerts_generated} new alerts generated.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      setMsg(`Detection error: ${err.message}`);
    } finally {
      setIsRunning(false);
      setTimeout(() => setMsg(null), 4000);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Reset all security logs, alerts, and relations to clean baseline?')) return;
    setIsResetting(true);
    try {
      await api.resetSimulation();
      setMsg('Database state cleanly reset to baseline.');
      if (onRefresh) onRefresh();
    } catch (err) {
      setMsg(`Reset failed: ${err.message}`);
    } finally {
      setIsResetting(false);
      setTimeout(() => setMsg(null), 4000);
    }
  };

  const isHealthy = systemHealth === 'NORMAL';

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="flex items-center justify-between px-6 py-3">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-md shadow-cyan-950/50">
            <Shield className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold tracking-wide text-slate-100 font-mono">
                TEMPORAL-SOC
              </span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-mono">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Intelligent Cyberattack Detection via Temporal Knowledge Representation
            </p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center gap-4">
          {msg && (
            <span className="text-xs px-3 py-1 rounded bg-slate-800 text-cyan-300 border border-cyan-500/30 animate-fade-in font-mono">
              {msg}
            </span>
          )}

          {/* System Health Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            {isHealthy ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-red-400 animate-bounce" />
            )}
            <span className="text-slate-400">Status:</span>
            <span className={isHealthy ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
              {systemHealth}
            </span>
          </div>

          {/* Run Detection */}
          <button
            onClick={handleRunDetection}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-medium text-xs font-mono transition-all disabled:opacity-50 shadow-md shadow-cyan-900/30"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isRunning ? 'animate-spin' : ''}`} />
            {isRunning ? 'Analyzing...' : 'Run Detection'}
          </button>

          {/* Reset Baseline */}
          <button
            onClick={handleReset}
            disabled={isResetting}
            title="Reset database to baseline"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition-all disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
            Reset State
          </button>
        </div>
      </div>
    </header>
  );
}
