import React, { useState, useEffect } from 'react';
import { Shield, Activity, Users, AlertTriangle } from 'lucide-react';
import './App.css';

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [threats, setThreats] = useState([]);
  const [agentStatus, setAgentStatus] = useState({});

  useEffect(() => {
    fetchDashboardData();
    fetchThreats();
    fetchAgentStatus();
    
    // Update setiap 5 detik
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
      console.error('Error fetching dashboard data:', error);
    }
  };

  const fetchThreats = async () => {
    try {
      const response = await fetch('/api/threats/log');
      const data = await response.json();
      setThreats(data.threats || []);
    } catch (error) {
      console.error('Error fetching threats:', error);
    }
  };

  const fetchAgentStatus = async () => {
    try {
      const response = await fetch('/api/agents/status');
      const data = await response.json();
      setAgentStatus(data);
    } catch (error) {
      console.error('Error fetching agent status:', error);
    }
  };

  if (!dashboardData) {
    return (
      <div className="loading">
        <Shield className="animate-spin" size={48} />
        <p>Loading AI Security Dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="header">
        <div className="header-content">
          <Shield size={32} />
          <h1>Infinite AI Security Platform</h1>
          <div className="status-indicator online">ONLINE</div>
        </div>
      </header>

      <div className="dashboard-grid">
        {/* Stats Cards */}
        <div className="stats-grid">
          <div className="stat-card">
            <Users size={24} />
            <div>
              <h3>{dashboardData.agents.active}/{dashboardData.agents.total}</h3>
              <p>AI Agents Active</p>
            </div>
          </div>
          
          <div className="stat-card">
            <AlertTriangle size={24} />
            <div>
              <h3>{dashboardData.threats.critical}</h3>
              <p>Critical Threats</p>
            </div>
          </div>
          
          <div className="stat-card">
            <Activity size={24} />
            <div>
              <h3>{dashboardData.labyrinth.nodes}</h3>
              <p>Labyrinth Nodes</p>
            </div>
          </div>
          
          <div className="stat-card">
            <Shield size={24} />
            <div>
              <h3>{dashboardData.labyrinth.intruders}</h3>
              <p>Trapped Intruders</p>
            </div>
          </div>
        </div>

        {/* Agent Status */}
        <div className="panel">
          <h2>AI Agent Status</h2>
          <div className="agent-list">
            {Object.entries(agentStatus).map(([name, status]) => (
              <div key={name} className="agent-item">
                <div className={`agent-status ${status.status}`}></div>
                <div>
                  <strong>{status.name}</strong>
                  <p>{status.model} - {status.tasks_completed} tasks</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Threats */}
        <div className="panel">
          <h2>Recent Threats</h2>
          <div className="threat-list">
            {threats.slice(-5).map((threat, index) => (
              <div key={index} className="threat-item">
                <div className="threat-severity high"></div>
                <div>
                  <strong>Threat #{threat.id}</strong>
                  <p>{threat.analysis?.threat_level || 'Unknown'} - {new Date(threat.timestamp).toLocaleTimeString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Labyrinth Visualization */}
        <div className="panel labyrinth-panel">
          <h2>Infinite Labyrinth Defense</h2>
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
              <p>🌀 Nodes: {dashboardData.labyrinth.nodes}</p>
              <p>🕷️ Intruders: {dashboardData.labyrinth.intruders}</p>
              <p>⚡ Traps: {dashboardData.labyrinth.traps_triggered}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;