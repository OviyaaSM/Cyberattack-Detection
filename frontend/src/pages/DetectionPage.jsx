import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  Clock,
  Server,
  User,
  CheckCircle,
  FileSearch,
} from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import RiskGauge from '../components/RiskGauge';

export default function DetectionPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const fetchAlerts = async () => {
    try {
      const params = {};
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.status = statusFilter;

      const res = await api.getAlerts(params);
      setAlerts(res.data || []);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter, statusFilter]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await api.updateAlertStatus(alertId, newStatus);
      fetchAlerts();
    } catch (err) {
      alert(`Failed to update alert: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" /> Detected Attack Patterns
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Coordinated cyberattacks detected through temporal knowledge representations and multi-stage reasoning.
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>

          <button
            onClick={fetchAlerts}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Alert Cards List */}
      {alerts.length === 0 ? (
        <div className="p-12 text-center rounded-xl border border-slate-800 bg-slate-900/60 font-mono text-slate-400 space-y-3">
          <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto" />
          <p className="text-sm">No attack alerts currently match your criteria.</p>
          <p className="text-xs text-slate-500">
            Use the Simulation Lab to inject multi-stage attack scenarios or run detection on ingested logs.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {alerts.map((alt) => {
            const affectedComps = JSON.parse(alt.affected_computers || '[]');
            const relatedUsers = JSON.parse(alt.related_users || '[]');
            const temporalInfo = JSON.parse(alt.temporal_constraints || '{}');

            return (
              <div
                key={alt.id}
                className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl hover:border-slate-700 transition-all space-y-4 font-mono"
              >
                {/* Alert Top Bar */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-3">
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400 font-bold">
                      {alt.id}
                    </span>
                    <h3 className="text-base font-semibold text-slate-100">
                      {alt.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alt.severity} size="lg" />
                    <span className="text-xs px-2.5 py-1 rounded-full bg-slate-950 border border-slate-800 text-slate-300">
                      {alt.status}
                    </span>
                  </div>
                </div>

                {/* Explanation */}
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                  {alt.explanation}
                </p>

                {/* Metadata & Risk Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  {/* Entity Bindings */}
                  <div className="space-y-2 p-3 rounded-lg bg-slate-950/40 border border-slate-800/60">
                    <div className="flex items-center gap-1.5 text-slate-400">
                      <Server className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Affected Hosts ({affectedComps.length}):</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {affectedComps.map((comp) => (
                        <span key={comp} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 text-[11px]">
                          {comp}
                        </span>
                      ))}
                    </div>

                    <div className="flex items-center gap-1.5 text-slate-400 pt-1">
                      <User className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Related Identities:</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {relatedUsers.map((usr) => (
                        <span key={usr} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px]">
                          {usr}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Temporal Constraints */}
                  <div className="space-y-1.5 p-3 rounded-lg bg-slate-950/40 border border-slate-800/60 text-[11px]">
                    <div className="flex items-center gap-1.5 text-slate-400">
                      <Clock className="w-3.5 h-3.5 text-amber-400" />
                      <span>Temporal Bounds:</span>
                    </div>
                    <p className="text-slate-300">
                      Window: {temporalInfo.temporal_window_minutes || 30} mins
                    </p>
                    <p className="text-slate-400 truncate">
                      Span: {new Date(alt.start_time).toLocaleTimeString()} &rarr; {new Date(alt.end_time).toLocaleTimeString()}
                    </p>
                    <p className="text-slate-500 text-[10px]">
                      Predicate: {temporalInfo.temporal_predicate || temporalInfo.temporal_chain || 'Satisfied'}
                    </p>
                  </div>

                  {/* Risk Score */}
                  <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/60 flex flex-col justify-center">
                    <RiskGauge score={alt.risk_score} />
                  </div>
                </div>

                {/* Footer Actions */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/60">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-500">Update Status:</span>
                    {['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
                      <button
                        key={st}
                        onClick={() => handleStatusChange(alt.id, st)}
                        disabled={alt.status === st}
                        className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-all ${
                          alt.status === st
                            ? 'bg-cyan-950 border-cyan-700 text-cyan-300 font-bold'
                            : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => navigate(`/timeline?alert_id=${alt.id}`)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors"
                    >
                      <Clock className="w-3.5 h-3.5" /> View Timeline
                    </button>

                    <button
                      onClick={() => navigate(`/investigation?alert_id=${alt.id}`)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs font-mono shadow-md shadow-cyan-900/30 transition-colors"
                    >
                      <FileSearch className="w-3.5 h-3.5" /> Investigate Incident <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
