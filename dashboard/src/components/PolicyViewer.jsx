import { useState, useEffect } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function PolicyViewer() {
  const [health, setHealth] = useState(null);
  const [reloading, setReloading] = useState(false);
  const [reloadResult, setReloadResult] = useState(null);

  useEffect(() => {
    async function load() {
      const res = await apiFetch('/health');
      if (res.ok) setHealth(res.data);
    }
    load();
  }, []);

  async function handleReload() {
    setReloading(true);
    setReloadResult(null);
    const res = await apiFetch('/policy/reload', { method: 'POST' });
    setReloading(false);
    if (res.ok) {
      setReloadResult({ ok: true, version: res.data.version, diff: res.data.diff });
    } else if (res.status === 403) {
      setReloadResult({ ok: false, error: 'Admin API key required for policy reload.' });
    } else {
      setReloadResult({ ok: false, error: 'Failed to reload policy.' });
    }
  }

  return (
    <div>
      <div className="card">
        <h3>Policy Status</h3>
        {health ? (
          <div>
            <p><strong>Policy Loaded:</strong> {health.policy_loaded ? 'Yes' : 'No'}</p>
            <p><strong>Version:</strong> {String(health.policy_version || 'unknown')}</p>
            <p><strong>DB Connected:</strong> {health.db_connected ? 'Yes' : 'No'}</p>
            <p><strong>Current EAS:</strong> {health.eas !== undefined ? `${(health.eas * 100).toFixed(0)}%` : '—'}</p>
          </div>
        ) : (
          <p>Loading...</p>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Policy Reload (Admin)</h3>
        <button
          className="btn btn-sm"
          onClick={handleReload}
          disabled={reloading}
        >
          {reloading ? 'Reloading...' : 'Reload Policy'}
        </button>

        {reloadResult && reloadResult.ok && (
          <div style={{ marginTop: 8 }}>
            <p style={{ color: 'var(--success)' }}>
              Policy reloaded — version: {String(reloadResult.version)}
            </p>
            {reloadResult.diff && (
              <pre>{String(reloadResult.diff)}</pre>
            )}
          </div>
        )}
        {reloadResult && !reloadResult.ok && (
          <p style={{ color: 'var(--danger)', marginTop: 8 }}>
            {String(reloadResult.error)}
          </p>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Risk Tiers Reference</h3>
        <table>
          <thead>
            <tr>
              <th>Tier</th>
              <th>Description</th>
              <th>Examples</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><span className="badge badge-permit">Tier 1</span></td>
              <td>Read-only operations</td>
              <td>show interfaces, show running-config, ping</td>
            </tr>
            <tr>
              <td><span className="badge badge-permit">Tier 2</span></td>
              <td>Low-risk changes</td>
              <td>Set interface description, configure logging</td>
            </tr>
            <tr>
              <td><span className="badge badge-escalate">Tier 3</span></td>
              <td>Medium-risk changes</td>
              <td>Configure VLAN, static route</td>
            </tr>
            <tr>
              <td><span className="badge badge-escalate">Tier 4</span></td>
              <td>High-risk changes</td>
              <td>Configure BGP neighbor, ACL</td>
            </tr>
            <tr>
              <td><span className="badge badge-block">Tier 5</span></td>
              <td>Critical operations</td>
              <td>Erase config, reload device</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
