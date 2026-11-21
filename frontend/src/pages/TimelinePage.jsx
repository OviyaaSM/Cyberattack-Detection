import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Clock,
  ArrowDown,
  Server,
  User,
  ShieldAlert,
  GitCommit,
  CheckCircle2,
  Filter,
} from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import Modal from '../components/Modal';

export default function TimelinePage() {
  const [searchParams] = useSearchParams();
  const alertIdParam = searchParams.get('alert_id');

  const [alerts, setAlerts] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState(alertIdParam || '');
  const [timelineData, setTimelineData] = useState({ events: [], relationships: [] });
  const [loading, setLoading] = useState(true);
  const [activeModalEvent, setActiveModalEvent] = useState(null);

  useEffect(() => {
    api.getAlerts().then((res) => {
      setAlerts(res.data || []);
      if (!selectedAlertId && res.data?.length > 0) {
        setSelectedAlertId(res.data[0].id);
      }
    }).catch(() => {});
  }, []);

  const fetchTimeline = async () => {
    setLoading(true);
    try {
      const params = {};
      if (selectedAlertId) params.alert_id = selectedAlertId;
      const res = await api.getTimeline(params);
      setTimelineData(res.data || { events: [], relationships: [] });
    } catch (err) {
      console.error('Failed to fetch timeline:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [selectedAlertId]);

  const { events, relationships } = timelineData;

  // Build causal candidate map by target_event_id
  const causalMap = {};
  relationships.forEach((r) => {
    if (r.relation_type === 'CAUSALLY_RELATED_CANDIDATE') {
      causalMap[r.target_event_id] = r;
    }
  });

  return (
    <div className="space-y-6">
      {/* Header & Alert Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Clock className="w-6 h-6 text-amber-400" /> Temporal Attack Timeline
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological reconstruction of correlated security events, interval constraints, and causal chains.
          </p>
        </div>

        {/* Scope Selector */}
        <div className="flex items-center gap-3">
          <select
            value={selectedAlertId}
            onChange={(e) => setSelectedAlertId(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 max-w-xs"
          >
            <option value="">Full Ingested Event Timeline</option>
            {alerts.map((a) => (
              <option key={a.id} value={a.id}>
                [{a.severity}] {a.title} ({a.id})
              </option>
            ))}
          </select>

          <button
            onClick={fetchTimeline}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
          >
            Reload
          </button>
        </div>
      </div>

      {/* Timeline Progression Container */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 text-xs font-mono text-slate-400">
          <span>Chronological Sequence Progression</span>
          <span>{events.length} Correlated Attack Events | {relationships.length} Temporal Constraints</span>
        </div>

        {events.length === 0 ? (
          <div className="text-center py-12 text-slate-500 font-mono text-xs">
            No events found for this scope. Select an active alert or inject a simulation scenario.
          </div>
        ) : (
          <div className="relative border-l-2 border-slate-700/80 ml-6 pl-8 space-y-8 my-4">
            {events.map((evt, idx) => {
              const isFirst = idx === 0;
              const isLast = idx === events.length - 1;
              const causalRel = causalMap[evt.event_id];
              const stageInfo = evt.stages && evt.stages.length > 0 ? evt.stages[0] : null;

              return (
                <div key={evt.event_id} className="relative group">
                  {/* Timeline Node Icon */}
                  <div
                    className={`absolute -left-[41px] top-1.5 w-6 h-6 rounded-full flex items-center justify-center border-2 ${
                      stageInfo
                        ? 'bg-red-950 border-red-500 text-red-400'
                        : 'bg-slate-900 border-cyan-500 text-cyan-400'
                    } font-mono text-[10px] font-bold shadow-lg shadow-black`}
                  >
                    {idx + 1}
                  </div>

                  {/* Event Card */}
                  <div
                    onClick={() => setActiveModalEvent(evt)}
                    className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 hover:border-slate-700 transition-all cursor-pointer space-y-3 shadow-md"
                  >
                    {/* Header: Stage, Event Type, Timestamp */}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {stageInfo && (
                          <span className="px-2 py-0.5 rounded bg-red-950/80 border border-red-800/60 text-red-400 font-bold text-xs font-mono">
                            Stage: {stageInfo.stage_name}
                          </span>
                        )}
                        <span className="font-semibold text-sm font-mono text-slate-100">
                          {evt.event_type}
                        </span>
                        <SeverityBadge severity={evt.severity} />
                      </div>

                      <div className="text-xs font-mono text-slate-400">
                        {new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)} UTC
                      </div>
                    </div>

                    {/* Action description */}
                    <p className="text-xs font-mono text-slate-300 leading-relaxed bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80">
                      {evt.action}
                    </p>

                    {/* Metadata entities */}
                    <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{evt.hostname} ({evt.computer_id})</span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{evt.user_id}</span>
                      </div>

                      <div className="text-slate-500 text-[11px]">
                        Socket: {evt.source_ip} &rarr; {evt.destination_ip}
                      </div>

                      {evt.session_id && (
                        <div className="text-slate-500 text-[11px]">
                          Session: {evt.session_id}
                        </div>
                      )}
                    </div>

                    {/* Causal Reasoning Explanation if present */}
                    {causalRel && (
                      <div className="p-2 rounded bg-amber-950/30 border border-amber-800/40 text-[11px] font-mono text-amber-300 flex items-center gap-2">
                        <GitCommit className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                        <span>Causal Link: {causalRel.evidence_text}</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Detail Modal */}
      <Modal
        isOpen={!!activeModalEvent}
        onClose={() => setActiveModalEvent(null)}
        title={activeModalEvent ? `Event: ${activeModalEvent.event_id}` : 'Event Details'}
      >
        {activeModalEvent && (
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-slate-950 border border-slate-800">
              <div>
                <span className="text-slate-500">Event Type:</span>
                <p className="text-slate-200 font-bold">{activeModalEvent.event_type}</p>
              </div>
              <div>
                <span className="text-slate-500">Severity:</span>
                <div><SeverityBadge severity={activeModalEvent.severity} /></div>
              </div>
              <div>
                <span className="text-slate-500">Host:</span>
                <p className="text-slate-300">{activeModalEvent.hostname} ({activeModalEvent.computer_id})</p>
              </div>
              <div>
                <span className="text-slate-500">User:</span>
                <p className="text-slate-300">{activeModalEvent.user_id}</p>
              </div>
              <div>
                <span className="text-slate-500">Network:</span>
                <p className="text-slate-300">{activeModalEvent.source_ip} &rarr; {activeModalEvent.destination_ip}</p>
              </div>
              <div>
                <span className="text-slate-500">Timestamp:</span>
                <p className="text-slate-300">{activeModalEvent.timestamp}</p>
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-semibold">Action:</span>
              <p className="p-3 mt-1 rounded bg-slate-950 border border-slate-800 text-slate-200">
                {activeModalEvent.action}
              </p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
