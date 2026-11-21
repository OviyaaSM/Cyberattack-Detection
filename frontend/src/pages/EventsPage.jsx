import React, { useState, useEffect } from 'react';
import {
  Activity,
  Search,
  Filter,
  RefreshCw,
  Terminal,
  Eye,
  Server,
} from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import Modal from '../components/Modal';

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [computers, setComputers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [selectedComp, setSelectedComp] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');

  // Selected event modal
  const [activeModalEvent, setActiveModalEvent] = useState(null);

  const fetchEvents = async () => {
    try {
      const params = { limit: 150 };
      if (selectedComp) params.computer_id = selectedComp;
      if (selectedType) params.event_type = selectedType;
      if (selectedSeverity) params.severity = selectedSeverity;
      if (search) params.search = search;

      const res = await api.getEvents(params);
      setEvents(res.data || []);
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    api.getComputers().then((res) => setComputers(res.data || [])).catch(() => {});
  }, []);

  useEffect(() => {
    fetchEvents();
    if (!autoRefresh) return;
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedComp, selectedType, selectedSeverity, search]);

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" /> Live Event Monitor
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time ingested and normalized security events across all monitored enterprise endpoints.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
              autoRefresh
                ? 'bg-cyan-950/60 border-cyan-800 text-cyan-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${autoRefresh ? 'bg-cyan-400 animate-pulse' : 'bg-slate-500'}`} />
            Auto-refresh: {autoRefresh ? 'ON (5s)' : 'PAUSED'}
          </button>

          <button
            onClick={fetchEvents}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Reload
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Search Input */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search action or host..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Computer Selector */}
        <select
          value={selectedComp}
          onChange={(e) => setSelectedComp(e.target.value)}
          className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Monitored Computers</option>
          {computers.map((c) => (
            <option key={c.id} value={c.id}>
              {c.hostname} ({c.id})
            </option>
          ))}
        </select>

        {/* Event Type Filter */}
        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
          className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Event Types</option>
          <option value="FAILED_LOGIN">FAILED_LOGIN</option>
          <option value="SUCCESSFUL_LOGIN">SUCCESSFUL_LOGIN</option>
          <option value="REMOTE_LOGIN">REMOTE_LOGIN</option>
          <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
          <option value="FILE_ACCESS">FILE_ACCESS</option>
          <option value="SENSITIVE_FILE_ACCESS">SENSITIVE_FILE_ACCESS</option>
          <option value="LARGE_DATA_TRANSFER">LARGE_DATA_TRANSFER</option>
          <option value="UNUSUAL_NETWORK_CONNECTION">UNUSUAL_NETWORK_CONNECTION</option>
          <option value="SUSPICIOUS_PROCESS">SUSPICIOUS_PROCESS</option>
        </select>

        {/* Severity Filter */}
        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>

      {/* Events Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-4 py-3">Timestamp (UTC)</th>
                <th className="px-4 py-3">Host / Computer</th>
                <th className="px-4 py-3">Event Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">User ID</th>
                <th className="px-4 py-3">Source &rarr; Dest</th>
                <th className="px-4 py-3">Action Details</th>
                <th className="px-4 py-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-slate-500">
                    No matching events found. Try adjusting filters or injecting simulation traffic.
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => setActiveModalEvent(evt)}
                  >
                    <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">
                      {new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-slate-500" />
                        <span>{evt.hostname}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <span className="font-semibold text-cyan-300">{evt.event_type}</span>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <SeverityBadge severity={evt.severity} />
                    </td>
                    <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">
                      {evt.user_id}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap text-[11px]">
                      {evt.source_ip} &rarr; {evt.destination_ip}
                    </td>
                    <td className="px-4 py-2.5 text-slate-300 max-w-xs truncate" title={evt.action}>
                      {evt.action}
                    </td>
                    <td className="px-4 py-2.5 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveModalEvent(evt);
                        }}
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-cyan-300 transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="px-4 py-2 bg-slate-950/80 border-t border-slate-800 text-[11px] text-slate-500 flex justify-between items-center font-mono">
          <span>Showing {events.length} security events</span>
          <span>Buffer window: up to 150 records</span>
        </div>
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
                <span className="text-slate-500">Timestamp:</span>
                <p className="text-slate-300">{activeModalEvent.timestamp}</p>
              </div>
              <div>
                <span className="text-slate-500">Status:</span>
                <p className="text-slate-300">{activeModalEvent.status}</p>
              </div>
              <div>
                <span className="text-slate-500">Computer ID:</span>
                <p className="text-slate-300">{activeModalEvent.computer_id} ({activeModalEvent.hostname})</p>
              </div>
              <div>
                <span className="text-slate-500">User Identity:</span>
                <p className="text-slate-300">{activeModalEvent.user_id}</p>
              </div>
              <div>
                <span className="text-slate-500">Source IP:</span>
                <p className="text-slate-300">{activeModalEvent.source_ip}</p>
              </div>
              <div>
                <span className="text-slate-500">Destination IP:</span>
                <p className="text-slate-300">{activeModalEvent.destination_ip}</p>
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-semibold">Action Description:</span>
              <p className="p-3 mt-1 rounded bg-slate-950 border border-slate-800 text-slate-200">
                {activeModalEvent.action}
              </p>
            </div>

            <div>
              <span className="text-slate-400 font-semibold">Metadata & Telemetry:</span>
              <pre className="p-3 mt-1 rounded bg-slate-950 border border-slate-800 text-cyan-300 overflow-x-auto text-[11px]">
                {JSON.stringify(JSON.parse(activeModalEvent.metadata_json || '{}'), null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
