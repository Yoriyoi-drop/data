import React, { useState, useEffect } from 'react';
import { Activity, Cpu, Zap, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

const AgentMonitor = () => {
  const [agents, setAgents] = useState({});
  const [performance, setPerformance] = useState({});
  const [loadBalance, setLoadBalance] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchAgentData();
    const interval = setInterval(fetchAgentData, 2000); // Update every 2 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchAgentData = async () => {
    try {
      // Fetch agent status
      const agentResponse = await fetch('/api/agents/status');
      const agentData = await agentResponse.json();
      setAgents(agentData);

      // Fetch performance metrics
      const perfResponse = await fetch('/api/agents/performance');
      const perfData = await perfResponse.json();
      setPerformance(perfData);

      // Fetch load balance info
      const loadResponse = await fetch('/api/agents/queue');
      const loadData = await loadResponse.json();
      setLoadBalance(loadData);

      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching agent data:', error);
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

  const getLoadColor = (load) => {
    if (load < 0.3) return '#00ff88';
    if (load < 0.7) return '#ffaa00';
    return '#ff4444';
  };

  if (isLoading) {
    return (
      <div className="agent-monitor loading">
        <Activity className="animate-spin" size={32} />
        <p>Loading agent data...</p>
      </div>
    );
  }

  return (
    <div className="agent-monitor">
      <div className="monitor-header">
        <h2>AI Agent Monitor</h2>
        <div className="system-stats">
          <div className="stat">
            <CheckCircle size={16} />
            <span>{performance.active_agents || 0}/{performance.total_agents || 0} Active</span>
          </div>
          <div className="stat">
            <Zap size={16} />
            <span>{performance.total_tasks_completed || 0} Tasks</span>
          </div>
          <div className="stat">
            <Activity size={16} />
            <span>{(performance.average_success_rate * 100 || 0).toFixed(1)}% Success</span>
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
              <div className="agent-model">{agent.model_type}</div>
            </div>

            <div className="agent-metrics">
              <div className="metric">
                <Cpu size={14} />
                <span>Load: {(agent.load_score * 100 || 0).toFixed(1)}%</span>
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
                <span>Uptime: {agent.uptime_hours || 0}h</span>
              </div>

              <div className="metric">
                <Activity size={14} />
                <span>Tasks: {agent.tasks_completed || 0}</span>
              </div>

              <div className="metric">
                <CheckCircle size={14} />
                <span>Success: {(agent.success_rate * 100 || 0).toFixed(1)}%</span>
              </div>
            </div>

            <div className="agent-capabilities">
              <h4>Capabilities</h4>
              <div className="capabilities-list">
                {(agent.capabilities || []).slice(0, 3).map((cap, index) => (
                  <span key={index} className="capability-tag">
                    {cap.replace('_', ' ')}
                  </span>
                ))}
                {(agent.capabilities || []).length > 3 && (
                  <span className="capability-tag more">
                    +{(agent.capabilities || []).length - 3} more
                  </span>
                )}
              </div>
            </div>

            {agent.status === 'error' && (
              <div className="agent-alert">
                <AlertTriangle size={14} />
                <span>Agent requires attention</span>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="queue-status">
        <h3>Task Queue Status</h3>
        <div className="queue-metrics">
          <div className="queue-metric">
            <span className="label">Queued Tasks:</span>
            <span className="value">{loadBalance.queued_tasks || 0}</span>
          </div>
          <div className="queue-metric">
            <span className="label">Processing:</span>
            <span className="value">{loadBalance.processing_tasks || 0}</span>
          </div>
          <div className="queue-metric">
            <span className="label">Auto-Assignment:</span>
            <span className={`value ${loadBalance.auto_assignment ? 'enabled' : 'disabled'}`}>
              {loadBalance.auto_assignment ? 'ON' : 'OFF'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentMonitor;