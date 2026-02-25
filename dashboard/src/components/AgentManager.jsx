import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function AgentManager() {
  const [agents, setAgents] = useState([]);
  const [error, setError] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null); // { agentId, action }

  const load = useCallback(async () => {
    const res = await apiFetch('/agents');
    if (res.ok) {
      setAgents(res.data.items || []);
      setError(null);
    } else if (res.status === 403 || res.status === 401) {
      setError('Agent management requires admin API key.');
    } else {
      setError('Agent management requires Phase 4 APIs.');
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [load]);

  async function performAction(agentId, action) {
    const res = await apiFetch(`/agents/${agentId}/${action}`, { method: 'POST' });
    if (res.ok) {
      setConfirmAction(null);
      load();
    }
  }

  if (error) {
    return <div className="empty">{error}</div>;
  }

  if (agents.length === 0) {
    return <div className="empty">No agents registered.</div>;
  }

  return (
    <div>
      <div className="card">
        <h3>Registered Agents ({agents.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>EAS</th>
              <th>Created</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.external_id}>
                <td>{String(a.name)}</td>
                <td>
                  <span className={`badge badge-${String(a.status).toLowerCase()}`}>
                    {String(a.status)}
                  </span>
                </td>
                <td>{(a.eas * 100).toFixed(0)}%</td>
                <td>{new Date(a.created_at).toLocaleDateString()}</td>
                <td>{a.last_seen ? new Date(a.last_seen).toLocaleString() : '—'}</td>
                <td>
                  <div className="actions">
                    {a.status === 'ACTIVE' && (
                      <button
                        className="btn btn-warning btn-sm"
                        onClick={() => setConfirmAction({ agentId: a.external_id, action: 'suspend', name: a.name })}
                      >
                        Suspend
                      </button>
                    )}
                    {a.status === 'SUSPENDED' && (
                      <button
                        className="btn btn-success btn-sm"
                        onClick={() => setConfirmAction({ agentId: a.external_id, action: 'activate', name: a.name })}
                      >
                        Activate
                      </button>
                    )}
                    {a.status !== 'REVOKED' && (
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => setConfirmAction({ agentId: a.external_id, action: 'revoke', name: a.name })}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {confirmAction && (
        <>
          <div className="overlay" onClick={() => setConfirmAction(null)} />
          <div className="confirm-dialog">
            <h3>Confirm {String(confirmAction.action)}</h3>
            <p>
              Are you sure you want to {String(confirmAction.action)} agent{' '}
              <strong>{String(confirmAction.name)}</strong>?
            </p>
            {confirmAction.action === 'revoke' && (
              <p style={{ color: 'var(--danger)' }}>This action is permanent and cannot be undone.</p>
            )}
            <div className="actions" style={{ marginTop: 12 }}>
              <button
                className="btn btn-danger btn-sm"
                onClick={() => performAction(confirmAction.agentId, confirmAction.action)}
              >
                Confirm
              </button>
              <button className="btn btn-sm" onClick={() => setConfirmAction(null)}>
                Cancel
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
