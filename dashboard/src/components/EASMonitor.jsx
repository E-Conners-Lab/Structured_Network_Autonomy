import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function EASMonitor() {
  const [eas, setEas] = useState(null);
  const [history, setHistory] = useState([]);
  const [adjustScore, setAdjustScore] = useState('');
  const [adjustReason, setAdjustReason] = useState('');
  const [adjustError, setAdjustError] = useState('');

  const load = useCallback(async () => {
    const [easRes, histRes] = await Promise.all([
      apiFetch('/eas'),
      apiFetch('/eas/history?page=1&page_size=20'),
    ]);
    if (easRes.ok) setEas(easRes.data);
    if (histRes.ok) setHistory(histRes.data.items || []);
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [load]);

  async function handleAdjust(e) {
    e.preventDefault();
    setAdjustError('');
    const score = parseFloat(adjustScore);
    if (isNaN(score) || score < 0 || score > 1) {
      setAdjustError('Score must be between 0.0 and 1.0');
      return;
    }
    if (!adjustReason.trim()) {
      setAdjustError('Reason is required');
      return;
    }
    const res = await apiFetch('/eas', {
      method: 'POST',
      body: { score, reason: adjustReason.trim() },
    });
    if (res.ok) {
      setAdjustScore('');
      setAdjustReason('');
      load();
    } else if (res.status === 403) {
      setAdjustError('Admin API key required for EAS adjustment.');
    } else {
      setAdjustError('Failed to adjust EAS.');
    }
  }

  return (
    <div>
      {eas && (
        <div className="card eas-gauge">
          <div className="score">{(eas.eas * 100).toFixed(0)}%</div>
          <div className="label">Current Earned Autonomy Score</div>
        </div>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Manual EAS Adjustment (Admin)</h3>
        <form onSubmit={handleAdjust} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
          <input
            type="number"
            step="0.01"
            min="0"
            max="1"
            placeholder="Score (0.0–1.0)"
            value={adjustScore}
            onChange={(e) => setAdjustScore(e.target.value)}
            style={{ width: 140, padding: '4px 8px' }}
          />
          <input
            placeholder="Reason"
            value={adjustReason}
            onChange={(e) => setAdjustReason(e.target.value)}
            style={{ flex: 1, minWidth: 200, padding: '4px 8px' }}
          />
          <button className="btn btn-sm" type="submit">Adjust</button>
        </form>
        {adjustError && <p style={{ color: 'var(--danger)', marginTop: 4, fontSize: '0.8rem' }}>{adjustError}</p>}
      </div>

      {history.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>EAS History</h3>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Score</th>
                <th>Previous</th>
                <th>Change</th>
                <th>Reason</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => {
                const delta = h.eas_score - h.previous_score;
                return (
                  <tr key={h.external_id}>
                    <td>{new Date(h.timestamp).toLocaleString()}</td>
                    <td>{(h.eas_score * 100).toFixed(1)}%</td>
                    <td>{(h.previous_score * 100).toFixed(1)}%</td>
                    <td style={{ color: delta >= 0 ? 'var(--success)' : 'var(--danger)' }}>
                      {delta >= 0 ? '+' : ''}{(delta * 100).toFixed(1)}%
                    </td>
                    <td>{String(h.change_reason)}</td>
                    <td>{String(h.source)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
