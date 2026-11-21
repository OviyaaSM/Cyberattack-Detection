import React, { useState } from 'react';
import {
  FlaskConical,
  Play,
  RotateCcw,
  ShieldAlert,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Server,
  Zap,
} from 'lucide-react';
import { api } from '../api/client';

const SCENARIOS = [
  {
    id: 'brute_force',
    title: 'Brute-force Account Compromise',
    description: 'Generates rapid failed authentication attempts followed by a successful login breaching the account.',
    stages: 'Credential Access &rarr; Initial Breach',
    severity: 'HIGH',
    color: 'border-orange-500/40 bg-orange-950/20 text-orange-400',
  },
  {
    id: 'lateral_movement',
    title: 'Lateral Movement Across Systems',
    description: 'Generates workstation foothold authentication followed by remote WMI/PowerShell connection to a Domain Controller.',
    stages: 'Foothold &rarr; Network Pivot',
    severity: 'HIGH',
    color: 'border-purple-500/40 bg-purple-950/20 text-purple-400',
  },
  {
    id: 'data_exfiltration',
    title: 'Sensitive File Staging & Exfiltration',
    description: 'Generates confidential financial archive access followed within 4 minutes by an outbound SFTP transfer to an untrusted IP.',
    stages: 'Data Staging &rarr; Exfiltration',
    severity: 'CRITICAL',
    color: 'border-red-500/40 bg-red-950/20 text-red-400',
  },
  {
    id: 'privilege_escalation',
    title: 'Privilege Escalation Chain',
    description: 'Generates normal user session followed by sudoers misconfiguration exploit to spawn root shell and access /etc/shadow.',
    stages: 'Normal Login &rarr; Sudo Exploit &rarr; Root Access',
    severity: 'HIGH',
    color: 'border-amber-500/40 bg-amber-950/20 text-amber-400',
  },
  {
    id: 'multi_stage',
    title: 'Coordinated Multi-Stage Cyberattack',
    description: 'Executes full 5-stage persistent APT campaign: Brute force &rarr; Breach &rarr; Lateral Pivot &rarr; Database Dump &rarr; Overseas Exfil.',
    stages: '5-Stage Full Attack Campaign',
    severity: 'CRITICAL',
    color: 'border-red-500 bg-red-950/40 text-red-300',
  },
];

export default function SimulationPage() {
  const [activeRunningId, setActiveRunningId] = useState(null);
  const [normalCount, setNormalCount] = useState(15);
  const [lastResult, setLastResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleInject = async (scenarioId) => {
    setActiveRunningId(scenarioId);
    setErrorMsg(null);
    try {
      const res = await api.startSimulation({ scenario_type: scenarioId });
      setLastResult(res.data);
    } catch (err) {
      setErrorMsg(`Simulation failed: ${err.message}`);
    } finally {
      setActiveRunningId(null);
    }
  };

  const handleNormalTraffic = async () => {
    setActiveRunningId('normal');
    setErrorMsg(null);
    try {
      const res = await api.startSimulation({ scenario_type: 'normal', event_count: Number(normalCount) });
      setLastResult(res.data);
    } catch (err) {
      setErrorMsg(`Traffic generation failed: ${err.message}`);
    } finally {
      setActiveRunningId(null);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Reset all security logs, alerts, and relations to clean baseline?')) return;
    setActiveRunningId('reset');
    try {
      await api.resetSimulation();
      setLastResult({ scenario: 'reset', message: 'All demo logs and alerts cleared cleanly.' });
    } catch (err) {
      setErrorMsg(`Reset failed: ${err.message}`);
    } finally {
      setActiveRunningId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
          <FlaskConical className="w-6 h-6 text-cyan-400" /> Simulation Laboratory
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Generate realistic synthetic background traffic or inject verifiable multi-stage cyberattack scenarios into the pipeline.
        </p>
      </div>

      {/* Result / Notification Banner */}
      {lastResult && (
        <div className="p-4 rounded-xl border border-cyan-800/60 bg-cyan-950/40 shadow-lg text-xs font-mono text-cyan-200 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2 font-bold text-cyan-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Simulation Execution Successful</span>
            </div>
            <p>
              Scenario: <span className="font-semibold">{lastResult.scenario || 'normal'}</span> | Generated Events: <span className="font-semibold">{lastResult.events_generated || 0}</span>
            </p>
            {lastResult.detection && (
              <p className="text-slate-300">
                Detection Results: {lastResult.detection.alerts_generated} alerts triggered, {lastResult.detection.temporal_relations_generated} temporal relations derived.
              </p>
            )}
          </div>
          <button
            onClick={() => setLastResult(null)}
            className="text-slate-400 hover:text-slate-200 text-xs"
          >
            &times;
          </button>
        </div>
      )}

      {errorMsg && (
        <div className="p-4 rounded-xl border border-red-800 bg-red-950/60 text-xs font-mono text-red-300">
          {errorMsg}
        </div>
      )}

      {/* Controls Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Normal Traffic Box */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" /> Benign Traffic Generator
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">Baseline</span>
          </div>

          <p className="text-slate-400 text-[11px] leading-relaxed">
            Generates realistic normal enterprise operations: employee console logins, document modifications, internal pings, and administrative checks.
          </p>

          <div className="space-y-2">
            <label className="text-slate-400 block">Number of Normal Events:</label>
            <input
              type="number"
              min="5"
              max="100"
              value={normalCount}
              onChange={(e) => setNormalCount(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
            />
          </div>

          <button
            onClick={handleNormalTraffic}
            disabled={activeRunningId === 'normal'}
            className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-mono transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-md shadow-cyan-900/30"
          >
            <Play className="w-4 h-4 fill-current" />
            {activeRunningId === 'normal' ? 'Generating...' : 'Inject Normal Traffic'}
          </button>
        </div>

        {/* Global Reset Box */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-amber-400" /> Database State Control
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">State</span>
          </div>

          <p className="text-slate-400 text-[11px] leading-relaxed">
            Clears all historical events, attack alerts, and temporal relations while restoring the simulated computers and detection rules to a clean baseline.
          </p>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-slate-400 text-[11px]">
            Restores 8 standard hosts: FIN-01, HR-02, DEV-03, ENG-04, DC-01, DB-01, FILE-01, WEB-01.
          </div>

          <button
            onClick={handleReset}
            disabled={activeRunningId === 'reset'}
            className="w-full py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-bold font-mono transition-all disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <RotateCcw className="w-4 h-4" />
            {activeRunningId === 'reset' ? 'Resetting...' : 'Reset to Clean State'}
          </button>
        </div>

        {/* Simulation Info */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4 font-mono text-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Zap className="w-4 h-4 text-yellow-400" /> Temporal Verification
              </h3>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed mt-3">
              Every injected scenario flows through the standard log ingestion API and database layer before temporal graph extraction and reasoning rules evaluate them.
            </p>
          </div>

          <div className="text-[10px] text-slate-500 border-t border-slate-800 pt-3">
            No simulated alerts are pre-fabricated; alerts are derived dynamically by the temporal engine.
          </div>
        </div>
      </div>

      {/* Predefined Attack Scenarios */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold font-mono text-slate-200">
          Predefined Multi-Stage Attack Scenarios
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {SCENARIOS.map((scen) => (
            <div
              key={scen.id}
              className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-3 font-mono flex flex-col justify-between hover:border-slate-700 transition-all"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${scen.color}`}>
                    {scen.severity}
                  </span>
                  <span className="text-[10px] text-slate-500">{scen.id}</span>
                </div>

                <h4 className="text-sm font-bold text-slate-100">{scen.title}</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">{scen.description}</p>
                <div className="text-[10px] text-cyan-400 font-semibold pt-1">
                  Stages: <span dangerouslySetInnerHTML={{ __html: scen.stages }} />
                </div>
              </div>

              <button
                onClick={() => handleInject(scen.id)}
                disabled={activeRunningId === scen.id}
                className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono font-bold transition-all disabled:opacity-50 flex items-center justify-center gap-2 mt-4"
              >
                <Play className="w-3.5 h-3.5 fill-current text-cyan-400" />
                {activeRunningId === scen.id ? 'Injecting & Reasoning...' : 'Inject Attack Scenario'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
