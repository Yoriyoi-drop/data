import React, { useState, useEffect } from 'react';
import { Activity, Shield, CheckCircle, Clock, Users } from 'lucide-react';

const AgentMonitor = () => {
  const [agents, setAgents] = useState({});
  const [performance, setPerformance] = useState({});
  const [loadBalance, setLoadBalance] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchAgentData();
    const interval = setInterval(fetchAgentData, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchAgentData = async () => {
    try {
      const agentResponse = await fetch('/api/agents/status');
      const agentData = await agentResponse.json();
      setAgents(agentData);

      const perfResponse = await fetch('/api/agents/performance');
      const perfData = await perfResponse.json();
      setPerformance(perfData);

      const loadResponse = await fetch('/api/agents/queue');
      const loadData = await loadResponse.json();
      setLoadBalance(loadData);

      setIsLoading(false);
    } catch (error) {
      // Silent error handling
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'idle': return '#00ff88';
      case 'busy': return '#ffaa00';
      case 'error': return '#ff4444';
      case 'maintenance': return '#888888';
      default: return '#cccccc';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'idle': return 'Siaga';
      case 'busy': return 'Aktif';
      case 'error': return 'Error';
      case 'maintenance': return 'Maintenance';
      default: return 'Unknown';
    }
  };

  const getLoadColor = (load) => {
    if (load < 0.3) return '#00ff88';
    if (load < 0.7) return '#ffaa00';
    return '#ff4444';
  };

  if (isLoading) {
    return (
      <div className="agent-monitor loading">
        <Activity className="animate-spin" size={32} />
        <p>Memuat data agen...</p>
      </div>
    );
  }

  return (
    <div className="agent-monitor">
      <div className="monitor-header">
        <h2>Monitor Agen AI</h2>
        <div className="system-stats">
          <div className="stat">
            <CheckCircle size={16} />
            <span>{performance.active_agents || 0}/{performance.total_agents || 0} Aktif</span>
          </div>
          <div className="stat">
            <Shield size={16} />
            <span>{performance.total_tasks_completed || 0} Tugas</span>
          </div>
          <div className="stat">
            <Activity size={16} />
            <span>{(performance.average_success_rate * 100 || 0).toFixed(1)}% Berhasil</span>
          </div>
        </div>
      </div>

      <div className="agents-grid">
        {Object.entries(agents).map(([name, agent]) => (
          <div key={name} className="agent-card">
            <div className="agent-header">
              <div className="agent-name">
                <div 
                  className="status-dot"
                  style={{ backgroundColor: getStatusColor(agent.status) }}
                ></div>
                <h3>{agent.name}</h3>
              </div>
              <div className="agent-status-text">{getStatusText(agent.status)}</div>
            </div>

            <div className="agent-metrics">
              <div className="metric">
                <Activity size={14} />
                <span>Beban: {(agent.load_score * 100 || 0).toFixed(1)}%</span>
                <div className="load-bar">
                  <div 
                    className="load-fill"
                    style={{ 
                      width: `${(agent.load_score * 100 || 0)}%`,
                      backgroundColor: getLoadColor(agent.load_score || 0)
                    }}
                  ></div>
                </div>
              </div>

              <div className="metric">
                <Clock size={14} />
                <span>Waktu Aktif: {agent.uptime_hours || 0} jam</span>
              </div>

              <div className="metric">
                <Shield size={14} />
                <span>Tugas Selesai: {agent.tasks_completed || 0}</span>
              </div>

              <div className="metric">
                <CheckCircle size={14} />
                <span>Tingkat Berhasil: {(agent.success_rate * 100 || 0).toFixed(1)}%</span>
              </div>
            </div>

            <div className="agent-capabilities">
              <h4>Kemampuan</h4>
              <div className="capabilities-list">
                {(agent.capabilities || ['Deteksi Ancaman', 'Analisis Keamanan', 'Respons Otomatis']).slice(0, 3).map((cap, index) => (
                  <span key={index} className="capability-tag">
                    {cap.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="queue-status">
        <h3>Status Antrian Tugas</h3>
        <div className="queue-metrics">
          <div className="queue-metric">
            <span className="label">Tugas Menunggu:</span>
            <span className="value">{loadBalance.queued_tasks || 0}</span>
          </div>
          <div className="queue-metric">
            <span className="label">Sedang Diproses:</span>
            <span className="value">{loadBalance.processing_tasks || 0}</span>
          </div>
          <div className="queue-metric">
            <span className="label">Penugasan Otomatis:</span>
            <span className={`value ${loadBalance.auto_assignment ? 'enabled' : 'disabled'}`}>
              {loadBalance.auto_assignment ? 'AKTIF' : 'NONAKTIF'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentMonitor;