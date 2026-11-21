import React, { useState, useEffect } from 'react';
import {
  Settings,
  Download,
  Upload,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Server,
  FileText,
  Save,
} from 'lucide-react';
import { api } from '../api/client';

export default function ReportsSettingsPage() {
  const [rules, setRules] = useState([]);
  const [health, setHealth] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [savingRuleId, setSavingRuleId] = useState(null);
  const [ruleEdits, setRuleEdits] = useState({});

  const fetchData = async () => {
    try {
      const [rRes, hRes] = await Promise.all([
        api.getRules(),
        api.getHealth(),
      ]);
      setRules(rRes.data || []);
      setHealth(hRes.data || null);
    } catch (err) {
      console.error('Failed to load settings data:', err);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadStatus(null);
    try {
      const res = await api.uploadEventsFile(file);
      setUploadStatus({
        success: true,
        message: `Successfully ingested ${res.data.inserted_count} events from ${file.name}. Errors: ${res.data.failed_count}`,
      });
    } catch (err) {
      setUploadStatus({
        success: false,
        message: `Upload failed: ${err.message}`,
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleExportAlerts = async (format = 'json') => {
    try {
      const res = await api.getAlerts({ limit: 500 });
      const alerts = res.data || [];

      let content = '';
      let filename = `cyberattack_alerts_${Date.now()}`;
      let mimeType = 'application/json';

      if (format === 'json') {
        content = JSON.stringify(alerts, null, 2);
        filename += '.json';
      } else {
        // CSV export
        mimeType = 'text/csv';
        filename += '.csv';
        const headers = ['id', 'rule_id', 'rule_name', 'title', 'severity', 'risk_score', 'start_time', 'end_time', 'status'];
        const rows = alerts.map((a) => [
          a.id,
          a.rule_id,
          `"${a.rule_name}"`,
          `"${a.title}"`,
          a.severity,
          a.risk_score,
          a.start_time,
          a.end_time,
          a.status,
        ]);
        content = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Export failed: ${err.message}`);
    }
  };

  const handleRuleChange = (ruleId, field, value) => {
    setRuleEdits((prev) => ({
      ...prev,
      [ruleId]: {
        ...(prev[ruleId] || {}),
        [field]: value,
      },
    }));
  };

  const handleSaveRule = async (rule) => {
    const edits = ruleEdits[rule.id];
    if (!edits) return;

    setSavingRuleId(rule.id);
    try {
      await api.updateRule(rule.id, edits);
      await fetchData();
      setRuleEdits((prev) => {
        const copy = { ...prev };
        delete copy[rule.id];
        return copy;
      });
    } catch (err) {
      alert(`Failed to save rule: ${err.message}`);
    } finally {
      setSavingRuleId(null);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
          <Settings className="w-6 h-6 text-cyan-400" /> Reports & Detection Configuration
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Export forensic alerts, import external CSV/JSON logs, and customize temporal detection thresholds.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dataset Ingestion & Upload */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" /> Import Security Log Dataset
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">CSV / JSON</span>
          </div>

          <p className="text-slate-400 leading-relaxed text-[11px]">
            Upload raw or normalized security event datasets. Columns are validated and mapped automatically into the temporal event store.
          </p>

          <div className="p-6 border-2 border-dashed border-slate-800 hover:border-slate-700 rounded-xl bg-slate-950/60 text-center space-y-3">
            <FileText className="w-8 h-8 text-slate-500 mx-auto" />
            <div className="text-slate-400 text-xs">
              <label className="cursor-pointer text-cyan-400 hover:text-cyan-300 font-bold underline">
                Click to browse files
                <input
                  type="file"
                  accept=".csv,.json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
              <p className="text-[10px] text-slate-500 mt-1">Supports standard CSV or JSON schema</p>
            </div>
            {isUploading && <p className="text-cyan-400 animate-pulse">Ingesting and parsing records...</p>}
          </div>

          {uploadStatus && (
            <div
              className={`p-3 rounded-lg border text-[11px] ${
                uploadStatus.success
                  ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                  : 'border-red-800 bg-red-950/40 text-red-300'
              }`}
            >
              {uploadStatus.message}
            </div>
          )}
        </div>

        {/* Forensic Export & System Diagnostic */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Download className="w-4 h-4 text-cyan-400" /> Forensic Incident Export
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">Export</span>
            </div>

            <p className="text-slate-400 leading-relaxed text-[11px]">
              Download full evidence bundles, temporal sequences, and risk score metrics for incident response reporting.
            </p>

            <div className="flex gap-3">
              <button
                onClick={() => handleExportAlerts('json')}
                className="flex-1 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-bold transition-all flex items-center justify-center gap-2"
              >
                <Download className="w-3.5 h-3.5" /> Export as JSON
              </button>
              <button
                onClick={() => handleExportAlerts('csv')}
                className="flex-1 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-bold transition-all flex items-center justify-center gap-2"
              >
                <Download className="w-3.5 h-3.5" /> Export as CSV
              </button>
            </div>
          </div>

          {/* System Environment Diagnostic */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-[11px]">
            <span className="text-slate-400 font-bold">System Health Diagnostic:</span>
            <div className="flex items-center justify-between text-slate-300 pt-1">
              <span>Service Status:</span>
              <span className="text-emerald-400 font-semibold">{health?.status || 'UP'}</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span>Database Connection:</span>
              <span className="text-emerald-400 font-semibold">{health?.database || 'HEALTHY'}</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span>API Gateway:</span>
              <span className="text-cyan-400">{health?.service || 'Temporal SOC Core'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Rules Customization Table */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" /> Detection Rules & Temporal Time-Windows
          </h3>
          <span className="text-[10px] text-slate-500">Configurable reasoning thresholds</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="px-3 py-2.5">Rule ID</th>
                <th className="px-3 py-2.5">Rule Name</th>
                <th className="px-3 py-2.5">Scenario</th>
                <th className="px-3 py-2.5">Severity</th>
                <th className="px-3 py-2.5">Time Window (Min)</th>
                <th className="px-3 py-2.5">Base Score</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="px-3 py-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {rules.map((rule) => {
                const edits = ruleEdits[rule.id] || {};
                const currentWindow = edits.time_window_minutes !== undefined ? edits.time_window_minutes : rule.time_window_minutes;
                const currentScore = edits.default_risk_score !== undefined ? edits.default_risk_score : rule.default_risk_score;
                const isEnabled = edits.is_enabled !== undefined ? edits.is_enabled : rule.is_enabled;
                const hasEdits = !!ruleEdits[rule.id];

                return (
                  <tr key={rule.id} className="hover:bg-slate-800/30">
                    <td className="px-3 py-2 text-cyan-400 font-bold">{rule.id}</td>
                    <td className="px-3 py-2 text-slate-200 font-semibold">{rule.name}</td>
                    <td className="px-3 py-2 text-slate-400">{rule.scenario}</td>
                    <td className="px-3 py-2">
                      <select
                        value={edits.severity || rule.severity}
                        onChange={(e) => handleRuleChange(rule.id, 'severity', e.target.value)}
                        className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-slate-200"
                      >
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                      </select>
                    </td>
                    <td className="px-3 py-2">
                      <input
                        type="number"
                        min="1"
                        max="180"
                        value={currentWindow}
                        onChange={(e) => handleRuleChange(rule.id, 'time_window_minutes', Number(e.target.value))}
                        className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-slate-200"
                      />
                    </td>
                    <td className="px-3 py-2">
                      <input
                        type="number"
                        min="10"
                        max="100"
                        value={currentScore}
                        onChange={(e) => handleRuleChange(rule.id, 'default_risk_score', Number(e.target.value))}
                        className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-slate-200"
                      />
                    </td>
                    <td className="px-3 py-2">
                      <button
                        onClick={() => handleRuleChange(rule.id, 'is_enabled', !isEnabled)}
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          isEnabled
                            ? 'bg-emerald-950 border-emerald-800 text-emerald-400'
                            : 'bg-slate-950 border-slate-800 text-slate-500'
                        }`}
                      >
                        {isEnabled ? 'ENABLED' : 'DISABLED'}
                      </button>
                    </td>
                    <td className="px-3 py-2 text-right">
                      {hasEdits && (
                        <button
                          onClick={() => handleSaveRule(rule)}
                          disabled={savingRuleId === rule.id}
                          className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-all disabled:opacity-50 flex items-center gap-1 ml-auto"
                        >
                          <Save className="w-3.5 h-3.5" />
                          {savingRuleId === rule.id ? 'Saving...' : 'Save'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
