import { useState } from 'react';
import { getApiKey, setApiKey, clearApiKey } from './hooks/useApi';
import SummaryCards from './components/SummaryCards';
import VerdictFeed from './components/VerdictFeed';
import EscalationPanel from './components/EscalationPanel';
import AuditExplorer from './components/AuditExplorer';
import AgentManager from './components/AgentManager';
import EASMonitor from './components/EASMonitor';
import PolicyViewer from './components/PolicyViewer';
import DeviceGrid from './components/DeviceGrid';
import TimelinePanel from './components/TimelinePanel';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'devices', label: 'Devices' },
  { id: 'escalations', label: 'Escalations' },
  { id: 'audit', label: 'Audit Log' },
  { id: 'agents', label: 'Agents' },
  { id: 'eas', label: 'EAS' },
  { id: 'policy', label: 'Policy' },
];

export default function App() {
  const [apiKey, setKey] = useState(getApiKey());
  const [keyInput, setKeyInput] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  function handleLogin(e) {
    e.preventDefault();
    if (keyInput.trim()) {
      setApiKey(keyInput.trim());
      setKey(keyInput.trim());
      setKeyInput('');
    }
  }

  function handleLogout() {
    clearApiKey();
    setKey('');
  }

  return (
    <div className="app">
      <header className="header">
        <h1>SNA Dashboard</h1>
        {apiKey ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--muted)' }}>Authenticated</span>
            <button className="btn btn-sm" onClick={handleLogout}>Logout</button>
          </div>
        ) : (
          <form className="login-form" onSubmit={handleLogin}>
            <input
              type="password"
              placeholder="API Key"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
            />
            <button type="submit" className="btn btn-sm">Login</button>
          </form>
        )}
      </header>

      {!apiKey ? (
        <div className="empty">Enter your SNA API key to access the dashboard.</div>
      ) : (
        <>
          <nav className="tabs">
            {TABS.map((t) => (
              <button
                key={t.id}
                className={`tab${activeTab === t.id ? ' active' : ''}`}
                onClick={() => setActiveTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </nav>

          {activeTab === 'overview' && (
            <div>
              <SummaryCards />
              <div style={{ marginTop: 16 }}>
                <VerdictFeed />
              </div>
            </div>
          )}
          {activeTab === 'timeline' && <TimelinePanel />}
          {activeTab === 'devices' && <DeviceGrid />}
          {activeTab === 'escalations' && <EscalationPanel />}
          {activeTab === 'audit' && <AuditExplorer />}
          {activeTab === 'agents' && <AgentManager />}
          {activeTab === 'eas' && <EASMonitor />}
          {activeTab === 'policy' && <PolicyViewer />}
        </>
      )}
    </div>
  );
}
