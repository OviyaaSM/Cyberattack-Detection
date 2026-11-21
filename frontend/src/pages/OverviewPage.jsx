import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Server,
  Activity,
  AlertTriangle,
  Flame,
  ArrowRight,
  TrendingUp,
  Clock,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { api } from '../api/client';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import RiskGauge from '../components/RiskGauge';

export default function OverviewPage() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [sumRes, trendRes, alertRes, evtRes] = await Promise.all([
        api.getDashboardSummary(),
        api.getDashboardTrends(),
        api.getAlerts({ limit: 5 }),
        api.getEvents({ limit: 6 }),
      ]);
      setSummary(sumRes.data);
      setTrends(trendRes.data.trends || []);
      setRecentAlerts(alertRes.data || []);
      setRecentEvents(evtRes.data || []);
    } catch (err) {
      console.error('Failed to load overview data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-full min-h-[400px]">
        <div className="text-center space-y-3 font-mono">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-sm text-slate-400">Loading Security Overview...</p>
        </div>
      </div>
    );
  }

  const riskData = summary?.risk_distribution
    ? [
        { name: 'Critical', count: summary.risk_distribution.CRITICAL || 0, color: '#ef4444' },
        { name: 'High', count: summary.risk_distribution.HIGH || 0, color: '#f97316' },
        { name: 'Medium', count: summary.risk_distribution.MEDIUM || 0, color: '#f59e0b' },
        { name: 'Low', count: summary.risk_distribution.LOW || 0, color: '#10b981' },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            Security Overview
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-host monitoring and temporal knowledge attack pattern correlation.
          </p>
        </div>
        <button
          onClick={fetchData}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
        >
          Refresh Feed
        </button>
      </div>

      {/* Stats Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Monitored Hosts"
          value={summary?.total_computers || 0}
          subtitle="Enterprise network workstations & servers"
          icon={Server}
          color="cyan"
        />
        <StatCard
          title="Processed Events"
          value={summary?.total_events || 0}
          subtitle="Normalized temporal security logs"
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Active Alerts"
          value={summary?.active_alerts || 0}
          subtitle="Correlated multi-stage alerts"
          icon={ShieldAlert}
          color={summary?.active_alerts > 0 ? 'amber' : 'emerald'}
        />
        <StatCard
          title="Critical Attacks"
          value={summary?.critical_alerts || 0}
          subtitle="High-severity breaches requiring response"
          icon={Flame}
          color="red"
          alert={(summary?.critical_alerts || 0) > 0}
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Event Timeline Activity Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200 font-mono">
                Temporal Activity Trend
              </h3>
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Events vs Alerts over Time</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGradient)"
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  name="Alerts"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#alertGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Breakdown */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 font-mono">
              Alert Severity Profile
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">Classification</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} tickLine={false} width={60} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Two Column Section: Recent Detected Attacks & Suspicious Events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Detected Attacks */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-slate-200 font-mono">
                Recent Detected Attack Patterns
              </h3>
            </div>
            <button
              onClick={() => navigate('/detection')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              View All <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {recentAlerts.length === 0 ? (
            <div className="text-center py-10 text-slate-500 text-xs font-mono">
              No cyberattacks currently detected. Run simulation or detection to evaluate.
            </div>
          ) : (
            <div className="space-y-3">
              {recentAlerts.map((alt) => (
                <div
                  key={alt.id}
                  onClick={() => navigate(`/investigation?alert_id=${alt.id}`)}
                  className="p-3.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950/60 transition-all cursor-pointer space-y-2 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors font-mono">
                      {alt.title}
                    </span>
                    <SeverityBadge severity={alt.severity} />
                  </div>

                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {alt.explanation}
                  </p>

                  <div className="pt-1">
                    <RiskGauge score={alt.risk_score} showDetails={false} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Security Events */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200 font-mono">
                Live Ingested Security Events
              </h3>
            </div>
            <button
              onClick={() => navigate('/events')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              Live Monitor <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {recentEvents.length === 0 ? (
            <div className="text-center py-10 text-slate-500 text-xs font-mono">
              No events ingested yet. Visit the Simulation Lab or upload a CSV dataset.
            </div>
          ) : (
            <div className="space-y-2">
              {recentEvents.map((evt) => (
                <div
                  key={evt.id}
                  className="flex items-center justify-between p-2.5 rounded-lg border border-slate-800/80 bg-slate-950/40 text-xs font-mono"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                    <div>
                      <div className="text-slate-200 font-medium">{evt.event_type}</div>
                      <div className="text-[11px] text-slate-400">{evt.hostname} — {evt.user_id}</div>
                    </div>
                  </div>
                  <SeverityBadge severity={evt.severity} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
