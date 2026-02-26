import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function EscalationPanel() {
  const [pending, setPending] = useState([]);
  const [selected, setSelected] = useState(null);
  const [reason, setReason] = useState('');
  const [decidedBy, setDecidedBy] = useState('');
  const [confirming, setConfirming] = useState(null); // 'APPROVED' | 'REJECTED' | null
  const [error, setError] = useState('');
  const [executing, setExecuting] = useState(false);
  const [execResults, setExecResults] = useState(null); // { tool_name, results: [{device, success, output, error}] }

  const load = useCallback(async () => {
    const res = await apiFetch('/escalation/pending');
    if (res.ok) setPending(res.data.items || []);
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  function closeModal() {
    setSelected(null);
    setConfirming(null);
    setReason('');
    setDecidedBy('');
    setError('');
    setExecuting(false);
    setExecResults(null);
  }

  async function submitDecision(decision) {
    if (!selected || !decidedBy.trim() || !reason.trim()) return;
    setError('');
    setExecResults(null);

    const res = await apiFetch(`/escalation/${selected.external_id}/decision`, {
      method: 'POST',
      body: { decision, decided_by: decidedBy.trim(), reason: reason.trim() },
    });

    if (!res.ok) {
      if (res.status === 403) {
        setError('Admin API key required. Log out and log in with the admin key.');
      } else {
        const msg = res.data?.detail || `Request failed (${res.status})`;
        setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
      }
      return;
    }

    if (decision === 'REJECTED') {
      closeModal();
      load();
      return;
    }

    // APPROVED — execute on devices
    setExecuting(true);
    try {
      const execRes = await apiFetch(`/escalation/${selected.external_id}/execute`, {
        method: 'POST',
      });
      if (execRes.ok) {
        setExecResults(execRes.data);
      } else {
        const msg = execRes.data?.detail || `Execution failed (${execRes.status})`;
        setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
      }
    } catch (e) {
      setError(`Execution error: ${e.message}`);
    } finally {
      setExecuting(false);
      load();
    }
  }

  if (pending.length === 0 && !selected) {
    return <div className="empty">No pending escalations.</div>;
  }

  return (
    <div>
      <div className="card">
        <h3>Pending Escalations ({pending.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Risk Tier</th>
              <th>Confidence</th>
              <th>Devices</th>
              <th>Senior</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {pending.map((e) => (
              <tr key={e.external_id}>
                <td>{String(e.tool_name)}</td>
                <td>{String(e.risk_tier)}</td>
                <td>{(e.confidence_score * 100).toFixed(0)}%</td>
                <td>{e.device_count}</td>
                <td>{e.requires_senior_approval ? 'Yes' : 'No'}</td>
                <td>
                  <button
                    className="btn btn-sm"
                    onClick={() => setSelected(e)}
                  >
                    Review
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <>
          <div className="overlay" onClick={closeModal} />
          <div className="confirm-dialog">
            <h3>Escalation Review</h3>
            <p><strong>Tool:</strong> {String(selected.tool_name)}</p>
            <p><strong>Risk Tier:</strong> {String(selected.risk_tier)}</p>
            <p><strong>Reason:</strong> {String(selected.reason)}</p>
            {selected.device_targets && (
              <p><strong>Targets:</strong> {selected.device_targets.map(String).join(', ')}</p>
            )}
            {selected.parameters && (
              <pre>{JSON.stringify(selected.parameters, null, 2)}</pre>
            )}
            {selected.requires_senior_approval && (
              <p><span className="badge badge-escalate">Requires Senior Approval</span></p>
            )}

            {!execResults && !executing && (
              <>
                <div style={{ marginTop: 12 }}>
                  <input
                    placeholder="Your name"
                    value={decidedBy}
                    onChange={(e) => setDecidedBy(e.target.value)}
                    style={{ marginRight: 8, padding: '4px 8px' }}
                  />
                  <input
                    placeholder="Decision reason"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    style={{ width: '100%', marginTop: 8, padding: '4px 8px' }}
                  />
                </div>

                {error && (
                  <p style={{ color: '#ff4444', marginTop: 8, fontSize: '0.9rem' }}>{error}</p>
                )}

                <div className="actions" style={{ marginTop: 12 }}>
                  <button
                    className="btn btn-success btn-sm"
                    onClick={() => submitDecision('APPROVED')}
                    disabled={!decidedBy.trim() || !reason.trim()}
                  >
                    Approve
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => submitDecision('REJECTED')}
                    disabled={!decidedBy.trim() || !reason.trim()}
                  >
                    Reject
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={closeModal}
                  >
                    Cancel
                  </button>
                </div>
              </>
            )}

            {executing && (
              <div style={{ marginTop: 16, textAlign: 'center' }}>
                <p style={{ color: '#4fc3f7', fontWeight: 600 }}>Executing on devices...</p>
              </div>
            )}

            {execResults && (
              <div style={{ marginTop: 16 }}>
                <h4 style={{ marginBottom: 8 }}>Execution Results</h4>
                {execResults.results.map((r, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '8px 12px',
                      marginBottom: 6,
                      borderRadius: 4,
                      background: r.success ? 'rgba(76, 175, 80, 0.15)' : 'rgba(244, 67, 54, 0.15)',
                      border: `1px solid ${r.success ? '#4caf50' : '#f44336'}`,
                    }}
                  >
                    <strong style={{ color: r.success ? '#4caf50' : '#f44336' }}>
                      {r.device}: {r.success ? 'Success' : 'Failed'}
                    </strong>
                    {r.output && (
                      <pre style={{ margin: '4px 0 0', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                        {r.output}
                      </pre>
                    )}
                    {r.error && (
                      <p style={{ margin: '4px 0 0', color: '#f44336', fontSize: '0.85rem' }}>
                        {r.error}
                      </p>
                    )}
                  </div>
                ))}

                {error && (
                  <p style={{ color: '#ff4444', marginTop: 8, fontSize: '0.9rem' }}>{error}</p>
                )}

                <div className="actions" style={{ marginTop: 12 }}>
                  <button className="btn btn-sm" onClick={closeModal}>
                    Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
