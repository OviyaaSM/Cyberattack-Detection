import axios from 'axios';

// VITE_API_URL can be set for production or defaults to local backend
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

export const api = {
  // Health
  getHealth: () => apiClient.get('/health'),

  // Events
  getEvents: (params) => apiClient.get('/events', { params }),
  createEvent: (data) => apiClient.post('/events', data),
  createBulkEvents: (data) => apiClient.post('/events/bulk', data),
  uploadEventsFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/events/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  // Computers
  getComputers: () => apiClient.get('/computers'),
  getComputer: (id) => apiClient.get(`/computers/${id}`),

  // Detection
  runDetection: () => apiClient.post('/detection/run'),
  getRules: () => apiClient.get('/detection/rules'),
  updateRule: (id, data) => apiClient.patch(`/detection/rules/${id}`, data),
  getDetectionResults: () => apiClient.get('/detection/results'),

  // Alerts
  getAlerts: (params) => apiClient.get('/alerts', { params }),
  getAlert: (id) => apiClient.get(`/alerts/${id}`),
  updateAlertStatus: (id, status) => apiClient.patch(`/alerts/${id}`, { status }),

  // Timeline
  getTimeline: (params) => apiClient.get('/timeline', { params }),

  // Network Graph
  getNetworkGraph: () => apiClient.get('/network/graph'),

  // Simulation
  startSimulation: (data) => apiClient.post('/simulation/start', data),
  stopSimulation: () => apiClient.post('/simulation/stop'),
  resetSimulation: () => apiClient.post('/simulation/reset'),

  // Investigation
  explainAlert: (alertId, useAi = false) => apiClient.post('/investigation/explain', { alert_id: alertId, use_ai: useAi }),
  getInvestigationReport: (alertId) => apiClient.get(`/investigation/${alertId}`),

  // Dashboard
  getDashboardSummary: () => apiClient.get('/dashboard/summary'),
  getDashboardTrends: () => apiClient.get('/dashboard/trends'),
};

export default apiClient;
