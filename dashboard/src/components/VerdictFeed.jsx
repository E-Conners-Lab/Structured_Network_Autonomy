import { useState, useEffect } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function VerdictFeed() {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let active = true;

    async function load() {
      const res = await apiFetch('/audit?page=1&page_size=25');
      if (!active) return;
      if (res.ok) {
        setEntries(res.data.items);
        setTotal(res.data.total);
      }
    }

    load();
    const id = setInterval(load, 5000);
    return () => { active = false; clearInterval(id); };
  }, []);

  if (entries.length === 0) {
    return <div className="empty">No audit entries yet.</div>;
  }

  return (
    <div className="card">
      <h3>Recent Verdicts ({total} total)</h3>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Verdict</th>
            <th>Risk Tier</th>
            <th>Confidence</th>
            <th>Devices</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.external_id}>
              <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
              <td>{String(e.tool_name)}</td>
              <td>
                <span className={`badge badge-${String(e.verdict).toLowerCase()}`}>
                  {String(e.verdict)}
                </span>
              </td>
              <td>{String(e.risk_tier)}</td>
              <td>{(e.confidence_score * 100).toFixed(0)}%</td>
              <td>{(e.device_targets || []).length > 0 ? e.device_targets.join(', ') : e.device_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
