import React, { useState, useEffect } from 'react';

const ThreatDashboard = () => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreats();
  }, []);

  const fetchThreats = async () => {
    try {
      const response = await fetch('/api/threats/log');
      const data = await response.json();
      setThreats(data.threats || []);
    } catch (error) {
      console.error('Failed to fetch threats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading threats...</div>;

  return (
    <div className="threat-dashboard">
      <h2>Threat Dashboard</h2>
      <div className="threat-stats">
        <div className="stat-card">
          <h3>Total Threats</h3>
          <p>{threats.length}</p>
        </div>
        <div className="stat-card">
          <h3>High Severity</h3>
          <p>{threats.filter(t => t.threat?.severity === 'high').length}</p>
        </div>
      </div>
      <div className="threat-list">
        {threats.map((threat, index) => (
          <div key={index} className="threat-item">
            <span className={`severity ${threat.threat?.severity}`}>
              {threat.threat?.severity || 'unknown'}
            </span>
            <span>{threat.threat?.type || 'unknown'}</span>
            <span>{threat.timestamp}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ThreatDashboard;
