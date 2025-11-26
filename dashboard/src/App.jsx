import React, { useState, useEffect } from 'react';
import { Shield, Activity, Users, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import './App.css';

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [threats, setThreats] = useState([]);
  const [agentStatus, setAgentStatus] = useState({});

  useEffect(() => {
    fetchDashboardData();
    fetchThreats();
    fetchAgentStatus();
    
    const interval = setInterval(() => {
      fetchDashboardData();
      fetchThreats();
    }, 5000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/dashboard/data');
      const data = await response.json();
      setDashboardData(data);
    } catch (error) {
      // Silent error handling
    }
  };

  const fetchThreats = async () => {
    try {
      const response = await fetch('/api/threats/log');
      const data = await response.json();
      setThreats(data.threats || []);
    } catch (error) {
      // Silent error handling
    }
  };

  const fetchAgentStatus = async () => {
    try {
      const response = await fetch('/api/agents/status');
      const data = await response.json();
      setAgentStatus(data);
    } catch (error) {
      // Silent error handling
    }
  };

  const getThreatSeverityText = (level) => {
    switch(level?.toLowerCase()) {
      case 'critical': return 'Ancaman Kritis';
      case 'high': return 'Ancaman Tinggi';
      case 'medium': return 'Ancaman Sedang';
      case 'low': return 'Ancaman Rendah';
      default: return 'Aktivitas Mencurigakan';
    }
  };

  const getAgentStatusText = (status) => {
    switch(status?.toLowerCase()) {
      case 'idle': return 'Siaga';
      case 'busy': return 'Aktif';
      case 'error': return 'Perlu Perhatian';
      default: return 'Online';
    }
  };

  if (!dashboardData) {
    return (
      <div className="loading">
        <Shield className="animate-spin" size={48} />
        <p>Memuat Dashboard Keamanan AI...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="header">
        <div className="header-content">
          <Shield size={32} />
          <h1>Platform Keamanan AI Infinite</h1>
          <div className="status-indicator online">AKTIF</div>
        </div>
      </header>

      <div className="dashboard-grid">
        <div className="stats-grid">
          <div className="stat-card">
            <Users size={24} />
            <div>
              <h3>{dashboardData.agents.active}/{dashboardData.agents.total}</h3>
              <p>Agen AI Aktif</p>
            </div>
          </div>
          
          <div className="stat-card">
            <AlertTriangle size={24} />
            <div>
              <h3>{dashboardData.threats.critical}</h3>
              <p>Ancaman Kritis</p>
            </div>
          </div>
          
          <div className="stat-card">
            <Activity size={24} />
            <div>
              <h3>{dashboardData.labyrinth.nodes}</h3>
              <p>Node Pertahanan</p>
            </div>
          </div>
          
          <div className="stat-card">
            <Shield size={24} />
            <div>
              <h3>{dashboardData.labyrinth.intruders}</h3>
              <p>Penyusup Terjebak</p>
            </div>
          </div>
        </div>

        <div className="panel">
          <h2>Status Agen AI</h2>
          <div className="agent-list">
            {Object.entries(agentStatus).map(([name, status]) => (
              <div key={name} className="agent-item">
                <div className={`agent-status ${status.status}`}></div>
                <div>
                  <strong>{status.name}</strong>
                  <p>{getAgentStatusText(status.status)} - {status.tasks_completed} tugas selesai</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <h2>Ancaman Terbaru</h2>
          <div className="threat-list">
            {threats.slice(-5).map((threat, index) => (
              <div key={index} className="threat-item">
                <div className="threat-severity high"></div>
                <div>
                  <strong>{getThreatSeverityText(threat.analysis?.threat_level)}</strong>
                  <p>Terdeteksi pada {new Date(threat.timestamp).toLocaleTimeString('id-ID')}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel labyrinth-panel">
          <h2>Pertahanan Labirin Infinite</h2>
          <div className="labyrinth-viz">
            <div className="maze-grid">
              {Array.from({length: 64}).map((_, i) => (
                <div 
                  key={i} 
                  className={`maze-cell ${Math.random() > 0.7 ? 'trap' : ''} ${Math.random() > 0.9 ? 'intruder' : ''}`}
                ></div>
              ))}
            </div>
            <div className="labyrinth-stats">
              <p>Node Aktif: {dashboardData.labyrinth.nodes}</p>
              <p>Penyusup Terjebak: {dashboardData.labyrinth.intruders}</p>
              <p>Jebakan Aktif: {dashboardData.labyrinth.traps_triggered}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;