import React, { useState, useEffect, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Share2, RefreshCw, Server, AlertTriangle, ShieldCheck, Activity } from 'lucide-react';
import { api } from '../api/client';

export default function NetworkPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const res = await api.getNetworkGraph();
      const rawNodes = res.data.nodes || [];
      const rawEdges = res.data.edges || [];

      // Calculate layout positions in circular or grid arrangement
      const nodeCount = rawNodes.length;
      const radius = 280;
      const centerX = 400;
      const centerY = 300;

      const flowNodes = rawNodes.map((n, idx) => {
        const angle = (idx / (nodeCount || 1)) * 2 * Math.PI;
        const x = centerX + radius * Math.cos(angle);
        const y = centerY + radius * Math.sin(angle);

        let borderColor = 'border-emerald-500/50';
        let bgGradient = 'from-slate-900 to-slate-950';
        let statusBadge = 'bg-emerald-950 text-emerald-400 border-emerald-800';

        if (n.status === 'COMPROMISED') {
          borderColor = 'border-red-500';
          bgGradient = 'from-red-950/40 to-slate-950';
          statusBadge = 'bg-red-950 text-red-400 border-red-800 animate-pulse';
        } else if (n.status === 'SUSPICIOUS') {
          borderColor = 'border-amber-500';
          bgGradient = 'from-amber-950/40 to-slate-950';
          statusBadge = 'bg-amber-950 text-amber-400 border-amber-800';
        }

        return {
          id: n.id,
          position: { x, y },
          data: {
            ...n,
            label: (
              <div className={`p-3 rounded-xl border ${borderColor} bg-gradient-to-b ${bgGradient} text-left font-mono min-w-[170px] shadow-lg shadow-black/80 hover:scale-105 transition-all`}>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <span className="font-bold text-xs text-slate-100 truncate">{n.id}</span>
                  </div>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full border font-bold ${statusBadge}`}>
                    {n.status}
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 truncate">{n.label}</div>
                <div className="text-[10px] text-cyan-400 mt-1 font-semibold">{n.ip}</div>
                {n.alert_count > 0 && (
                  <div className="mt-1 text-[10px] text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> {n.alert_count} Active Alerts
                  </div>
                )}
              </div>
            ),
          },
        };
      });

      const flowEdges = rawEdges.map((e) => {
        const isAttack = e.type === 'attack_path';
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          animated: isAttack,
          style: {
            stroke: isAttack ? '#ef4444' : '#06b6d4',
            strokeWidth: isAttack ? 3 : 1.5,
            strokeDasharray: isAttack ? '5,5' : undefined,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isAttack ? '#ef4444' : '#06b6d4',
          },
          data: e,
        };
      });

      setNodes(flowNodes);
      setEdges(flowEdges);
      if (flowNodes.length > 0 && !selectedNode) {
        setSelectedNode(flowNodes[0].data);
      }
    } catch (err) {
      console.error('Failed to load network graph:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  const onNodeClick = useCallback((event, node) => {
    setSelectedNode(node.data);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-mono text-slate-100 flex items-center gap-2">
            <Share2 className="w-6 h-6 text-cyan-400" /> Network Attack Visualization
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Topological attack path progression and cross-computer pivoting graph (React Flow).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-4 text-xs font-mono text-slate-400 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Healthy Host
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" /> Compromised Host
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-red-500 border-b border-dashed" /> Attack Pivot Path
            </span>
          </div>

          <button
            onClick={fetchGraph}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Recompute Graph
          </button>
        </div>
      </div>

      {/* Main Canvas & Details Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* React Flow Canvas */}
        <div className="lg:col-span-3 h-[600px] rounded-xl border border-slate-800 bg-slate-950/80 shadow-2xl relative overflow-hidden">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
          >
            <Background color="#1e293b" gap={20} size={1} />
            <Controls className="bg-slate-900 border-slate-800 text-slate-200 fill-slate-200" />
            <MiniMap
              nodeColor={(n) => (n.data?.status === 'COMPROMISED' ? '#ef4444' : '#06b6d4')}
              className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden"
            />
          </ReactFlow>
        </div>

        {/* Selected Endpoint Inspection Panel */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-xl space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" /> Endpoint Telemetry
            </h3>
            {selectedNode && (
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  selectedNode.status === 'COMPROMISED'
                    ? 'bg-red-950 text-red-400 border border-red-800'
                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}
              >
                {selectedNode.status}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-4">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div>
                  <span className="text-slate-500">Computer ID:</span>
                  <p className="text-slate-100 font-bold">{selectedNode.id}</p>
                </div>
                <div>
                  <span className="text-slate-500">Hostname:</span>
                  <p className="text-cyan-300">{selectedNode.label?.props ? selectedNode.id : selectedNode.label}</p>
                </div>
                <div>
                  <span className="text-slate-500">IP Address:</span>
                  <p className="text-slate-300">{selectedNode.ip}</p>
                </div>
                <div>
                  <span className="text-slate-500">Role:</span>
                  <p className="text-slate-300">{selectedNode.role}</p>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold">Active Threat Alerts:</span>
                <div className="mt-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <span className="text-2xl font-bold text-red-400">{selectedNode.alert_count || 0}</span>
                  <p className="text-[10px] text-slate-500 mt-1">Associated attack detection alerts</p>
                </div>
              </div>

              <div className="text-[11px] text-slate-400 leading-relaxed border-t border-slate-800 pt-3">
                Click any endpoint node on the canvas to inspect its role, status, and active attack vector correlations.
              </div>
            </div>
          ) : (
            <div className="text-center py-10 text-slate-500">
              Select an endpoint node to inspect telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
