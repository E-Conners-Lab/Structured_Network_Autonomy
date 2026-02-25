import { useState, useEffect } from 'react';
import { apiFetch } from '../hooks/useApi';

export default function SummaryCards() {
  const [report, setReport] = useState(null);
  const [eas, setEas] = useState(null);

  useEffect(() => {
    let active = true;

    async function load() {
      const [compRes, easRes] = await Promise.all([
        apiFetch('/reports/compliance?hours=24'),
        apiFetch('/eas'),
      ]);
      if (!active) return;
      if (compRes.ok) setReport(compRes.data);
      if (easRes.ok) setEas(easRes.data);
    }

    load();
    const id = setInterval(load, 15000);
    return () => { active = false; clearInterval(id); };
  }, []);

  if (!report) return <div className="empty">Loading summary...</div>;

  return (
    <div>
      <div className="grid">
        <div className="card">
          <h3>Total Evaluations (24h)</h3>
          <div className="value">{report.total_evaluations}</div>
        </div>
        <div className="card">
          <h3>Permitted</h3>
          <div className="value permit">{report.permit_count}</div>
        </div>
        <div className="card">
          <h3>Escalated</h3>
          <div className="value escalate">{report.escalate_count}</div>
        </div>
        <div className="card">
          <h3>Blocked</h3>
          <div className="value block">{report.block_count}</div>
        </div>
      </div>

      {eas && (
        <div className="card eas-gauge">
          <div className="score">{(eas.eas * 100).toFixed(0)}%</div>
          <div className="label">Earned Autonomy Score</div>
        </div>
      )}

      {(report.top_escalated_tools || []).length > 0 && (
        <div className="card">
          <h3>Top Escalated Tools</h3>
          <table>
            <thead>
              <tr><th>Tool</th><th>Count</th></tr>
            </thead>
            <tbody>
              {report.top_escalated_tools.map((t, i) => (
                <tr key={i}>
                  <td>{String(t.tool_name)}</td>
                  <td>{Number(t.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
