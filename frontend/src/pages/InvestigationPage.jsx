import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  FileSearch,
  Bot,
  ShieldAlert,
  Server,
  User,
  Clock,
  CheckCircle,
  AlertOctagon,
  Sparkles,
  Download,
  Terminal,
} from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import RiskGauge from '../components/RiskGauge';

export default function InvestigationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const alertIdParam = searchParams.get('alert_id');

  const [alerts, setAlerts] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState(alertIdParam || '');
  const [alertData, setAlertData] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState(false);

  useEffect(() => {
    api.getAlerts().then((res) => {
      setAlerts(res.data || []);
      if (!selectedAlertId && res.data?.length > 0) {
        setSelectedAlertId(res.data[0].id);
      }
    }).catch(() => {});
  }, []);

  const loadAlertDetails = async () => {
    if (!selectedAlertId) return;
    setLoading(true);
    try {
      const [altRes, rptRes] = await Promise.all([
        api.getAlert(selectedAlertId),
        api.getInvestigationReport(selectedAlertId).catch(() => ({ data: null })),
      ]);
      setAlertData(altRes.data);
      setReport(rptRes.data);
    } catch (err) {
      console.error('Failed to load alert details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedAlertId) {
      setSearchParams({ alert_id: selectedAlertId });
      loadAlertDetails();
    }
  }, [selectedAlertId]);

  const handleGenerateReport = async (useAi = false) => {
    if (!selectedAlertId) return;
    setGeneratingReport(true);
    try {
      const res = await api.explainAlert(selectedAlertId, useAi);
      setReport(res.data);
    } catch (err) {
      alert(`Report generation failed: ${err.message}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleStatusUpdate = async (newStatus) => {
    if (!selectedAlertId) return;
    try {
      const res = await api.updateAlertStatus(selectedAlertId, newStatus);
      setAlertData(res.data);
      const updatedList = alerts.map((a) => (a.id === selectedAlertId ? { ...a, status: newStatus } : a));
      setAlerts(updatedList);
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const affectedComps = alertData ? JSON.parse(alertData.affected_computers || '[]') : [];
  const relatedUsers = alertData ? JSON.parse(alertData.related_users || '[]') : [];
  const temporalInfo = alertData ? JSON.parse(alertData.temporal_constraints || '{}') : {};
  const recommendedActions = report ? JSON.parse(report.recommended_actions || '[]') : [];

  return (
    <div className="space-y-6">
      {/* Header & Alert Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <FileSearch className="w-6 h-6 text-cyan-400" /> Incident Investigation Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Forensic analysis, sequential evidence correlation, and defensive containment playbooks.
          </p>
        </div>

        {/* Selector */}
        <div className="flex items-center gap-3">
          <select
            value={selectedAlertId}
            onChange={(e) => setSelectedAlertId(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 max-w-sm"
          >
            {alerts.length === 0 && <option value="">No alerts available</option>}
            {alerts.map((a) => (
              <option key={a.id} value={a.id}>
                [{a.severity}] {a.title} ({a.id})
              </option>
            ))}
          </select>
        </div>
      </div>

      {!alertData ? (
        <div className="p-12 text-center rounded-xl border border-slate-800 bg-slate-900/60 font-mono text-slate-400">
          No alert selected for investigation. Select an alert from the dropdown above.
        </div>
      ) : (
        <div className="space-y-6 font-mono text-xs">
          {/* Top Overview Banner */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <span className="text-xs px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-cyan-400 font-bold">
                  {alertData.id}
                </span>
                <h2 className="text-base font-bold text-slate-100">{alertData.title}</h2>
              </div>

              <div className="flex items-center gap-3">
                <SeverityBadge severity={alertData.severity} size="lg" />
                <div className="flex items-center gap-1.5 text-slate-400 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800">
                  <span>Status:</span>
                  <span className="text-cyan-300 font-bold">{alertData.status}</span>
                </div>
              </div>
            </div>

            {/* Quick stats grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500">Detection Rule:</span>
                <p className="text-slate-200 font-bold">{alertData.rule_name}</p>
                <p className="text-slate-500 text-[10px]">{alertData.rule_id}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500">Affected Hosts ({affectedComps.length}):</span>
                <p className="text-cyan-300 font-semibold">{affectedComps.join(', ') || 'None'}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500">Identities Investigated:</span>
                <p className="text-slate-200 font-semibold">{relatedUsers.join(', ') || 'N/A'}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-center">
                <RiskGauge score={alertData.risk_score} />
              </div>
            </div>

            {/* Status Change Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
              <div className="flex items-center gap-2">
                <span className="text-slate-500">Triage Action:</span>
                {['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
                  <button
                    key={st}
                    onClick={() => handleStatusUpdate(st)}
                    disabled={alertData.status === st}
                    className={`px-2.5 py-1 rounded text-[11px] border transition-all ${
                      alertData.status === st
                        ? 'bg-cyan-950 border-cyan-600 text-cyan-300 font-bold'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleGenerateReport(false)}
                  disabled={generatingReport}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-bold transition-all disabled:opacity-50"
                >
                  Generate Deterministic Report
                </button>
                <button
                  onClick={() => handleGenerateReport(true)}
                  disabled={generatingReport}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-all disabled:opacity-50 shadow-md shadow-cyan-900/30"
                >
                  <Sparkles className="w-3.5 h-3.5 fill-current" />
                  {generatingReport ? 'Analyzing Evidence...' : 'AI Investigation Assistant'}
                </button>
              </div>
            </div>
          </div>

          {/* Sequential Evidence Table */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" /> Correlated Attack Evidence Chain
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-3 py-2.5">Step</th>
                    <th className="px-3 py-2.5">Attack Stage</th>
                    <th className="px-3 py-2.5">Host</th>
                    <th className="px-3 py-2.5">Event Type</th>
                    <th className="px-3 py-2.5">Role in Attack Sequence</th>
                    <th className="px-3 py-2.5">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {alertData.evidence && alertData.evidence.length > 0 ? (
                    alertData.evidence.map((ev) => (
                      <tr key={ev.id} className="hover:bg-slate-800/30">
                        <td className="px-3 py-2 font-bold text-cyan-400">#{ev.sequence_order}</td>
                        <td className="px-3 py-2">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-semibold">
                            {ev.stage_name}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-300">
                          {ev.event ? ev.event.hostname : 'N/A'}
                        </td>
                        <td className="px-3 py-2 text-cyan-300">
                          {ev.event ? ev.event.event_type : 'N/A'}
                        </td>
                        <td className="px-3 py-2 text-slate-300">{ev.role_in_attack}</td>
                        <td className="px-3 py-2 text-slate-400 whitespace-nowrap">
                          {ev.event ? new Date(ev.event.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="text-center py-6 text-slate-500">
                        No individual evidence steps recorded.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Investigation Report Card */}
          {report && (
            <div className="p-6 rounded-xl border border-cyan-800/60 bg-slate-900/90 shadow-2xl space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Bot className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-sm font-bold text-slate-100">
                    Formal Investigation Report ({report.id})
                  </h3>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                  Engine: {report.generated_by}
                </span>
              </div>

              {/* Summary */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Executive Summary</h4>
                <p className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 leading-relaxed">
                  {report.summary}
                </p>
              </div>

              {/* Technical Analysis */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Technical Analysis & Evidence Grounding</h4>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 whitespace-pre-wrap leading-relaxed">
                  {report.technical_analysis}
                </pre>
              </div>

              {/* Temporal Analysis */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Temporal Knowledge & Constraint Proof</h4>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-amber-300 whitespace-pre-wrap leading-relaxed">
                  {report.temporal_analysis}
                </pre>
              </div>

              {/* Recommended Actions */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Recommended Defensive Containment Playbook
                </h4>
                <div className="space-y-2">
                  {recommendedActions.map((act, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300"
                    >
                      <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
