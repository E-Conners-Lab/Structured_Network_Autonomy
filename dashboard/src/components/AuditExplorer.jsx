import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function AuditExplorer() {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState(null);
  const pageSize = 20;

  const load = useCallback(async () => {
    const res = await apiFetch(`/audit?page=${page}&page_size=${pageSize}`);
    if (res.ok) {
      setEntries(res.data.items);
      setTotal(res.data.total);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function exportJson() {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit-export.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3>Audit Log ({total} entries)</h3>
        <button className="btn btn-sm" onClick={exportJson}>Export JSON</button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Verdict</th>
            <th>Risk Tier</th>
            <th>Confidence</th>
            <th>EAS</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <>
              <tr
                key={e.external_id}
                onClick={() => setExpanded(expanded === e.external_id ? null : e.external_id)}
                style={{ cursor: 'pointer' }}
              >
                <td>{new Date(e.timestamp).toLocaleString()}</td>
                <td>{String(e.tool_name)}</td>
                <td>
                  <span className={`badge badge-${String(e.verdict).toLowerCase()}`}>
                    {String(e.verdict)}
                  </span>
                </td>
                <td>{String(e.risk_tier)}</td>
                <td>{(e.confidence_score * 100).toFixed(0)}%</td>
                <td>{(e.eas_at_time * 100).toFixed(0)}%</td>
              </tr>
              {expanded === e.external_id && (
                <tr key={`${e.external_id}-detail`}>
                  <td colSpan={6}>
                    <div style={{ padding: 8 }}>
                      <p><strong>Reason:</strong> {String(e.reason)}</p>
                      <p><strong>Devices:</strong> {(e.device_targets || []).length > 0 ? e.device_targets.join(', ') : e.device_count}</p>
                      <p><strong>Requires Audit:</strong> {e.requires_audit ? 'Yes' : 'No'}</p>
                      <p><strong>Senior Approval:</strong> {e.requires_senior_approval ? 'Yes' : 'No'}</p>
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
        <button className="btn btn-sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}>
          Prev
        </button>
        <span style={{ lineHeight: '28px', fontSize: '0.875rem' }}>
          Page {page} of {totalPages}
        </span>
        <button className="btn btn-sm" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
          Next
        </button>
      </div>
    </div>
  );
}
