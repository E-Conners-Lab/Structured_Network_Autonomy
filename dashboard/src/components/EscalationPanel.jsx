import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function EscalationPanel() {
  const [pending, setPending] = useState([]);
  const [selected, setSelected] = useState(null);
  const [reason, setReason] = useState('');
  const [decidedBy, setDecidedBy] = useState('');
  const [confirming, setConfirming] = useState(null); // 'APPROVED' | 'REJECTED' | null

  const load = useCallback(async () => {
    const res = await apiFetch('/escalation/pending');
    if (res.ok) setPending(res.data.items || []);
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  async function submitDecision(decision) {
    if (!selected || !decidedBy.trim() || !reason.trim()) return;
    const res = await apiFetch(`/escalation/${selected.external_id}/decision`, {
      method: 'POST',
      body: { decision, decided_by: decidedBy.trim(), reason: reason.trim() },
    });
    if (res.ok) {
      setSelected(null);
      setReason('');
      setDecidedBy('');
      setConfirming(null);
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
          <div className="overlay" onClick={() => { setSelected(null); setConfirming(null); }} />
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
                onClick={() => { setSelected(null); setConfirming(null); }}
              >
                Cancel
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
