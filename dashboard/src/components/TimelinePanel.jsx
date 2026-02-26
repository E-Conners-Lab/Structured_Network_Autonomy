import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

const EVENT_TYPE_OPTIONS = [
  { value: 'policy_decision', label: 'Policy Decision' },
  { value: 'escalation_created', label: 'Escalation Created' },
  { value: 'escalation_resolved', label: 'Escalation Resolved' },
  { value: 'device_execution', label: 'Device Execution' },
  { value: 'eas_change', label: 'EAS Change' },
  { value: 'policy_change', label: 'Policy Change' },
];

const DOT_COLORS = {
  policy_decision: '#0f766e',
  escalation_created: '#d97706',
  escalation_resolved: '#16a34a',
  device_execution: '#14b8a6',
  eas_change: '#64748b',
  policy_change: '#7c3aed',
};

const BADGE_CLASS = {
  policy_decision: 'badge-permit',
  escalation_created: 'badge-escalate',
  escalation_resolved: 'badge-approved',
  device_execution: 'badge-permit',
  eas_change: 'badge-pending',
  policy_change: 'badge-rejected',
};

function formatEventType(type) {
  return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export default function TimelinePanel() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState(null);
  const [selectedTypes, setSelectedTypes] = useState(new Set(EVENT_TYPE_OPTIONS.map(o => o.value)));
  const [toolFilter, setToolFilter] = useState('');
  const [deviceFilter, setDeviceFilter] = useState('');
  const pageSize = 50;

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    params.set('page', String(page));
    params.set('page_size', String(pageSize));
    if (selectedTypes.size > 0 && selectedTypes.size < EVENT_TYPE_OPTIONS.length) {
      params.set('event_types', Array.from(selectedTypes).join(','));
    }
    if (toolFilter.trim()) params.set('tool_name', toolFilter.trim());
    if (deviceFilter.trim()) params.set('device', deviceFilter.trim());

    const res = await apiFetch(`/timeline?${params.toString()}`);
    if (res.ok) {
      setEvents(res.data.items);
      setTotal(res.data.total);
    }
  }, [page, selectedTypes, toolFilter, deviceFilter]);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function toggleType(type) {
    setSelectedTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
    setPage(1);
  }

  return (
    <div className="card">
      <h3>Activity Timeline ({total} events)</h3>

      <div className="timeline-filters">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          {EVENT_TYPE_OPTIONS.map(opt => (
            <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.8rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={selectedTypes.has(opt.value)}
                onChange={() => toggleType(opt.value)}
              />
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: DOT_COLORS[opt.value], display: 'inline-block' }} />
              {opt.label}
            </label>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <input
            type="text"
            placeholder="Filter by tool name..."
            value={toolFilter}
            onChange={e => { setToolFilter(e.target.value); setPage(1); }}
            style={{ padding: '4px 8px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: '0.8rem', width: 180 }}
          />
          <input
            type="text"
            placeholder="Filter by device..."
            value={deviceFilter}
            onChange={e => { setDeviceFilter(e.target.value); setPage(1); }}
            style={{ padding: '4px 8px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: '0.8rem', width: 180 }}
          />
        </div>
      </div>

      {events.length === 0 ? (
        <div className="empty">No timeline events found.</div>
      ) : (
        <div className="timeline">
          {events.map(evt => (
            <div
              key={evt.id}
              className="timeline-event"
              onClick={() => setExpanded(expanded === evt.id ? null : evt.id)}
              style={{ cursor: 'pointer' }}
            >
              <div
                className="timeline-event-dot"
                style={{ background: DOT_COLORS[evt.event_type] || '#64748b' }}
              />
              <div className="timeline-event-content">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 4 }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>
                    {new Date(evt.timestamp).toLocaleString()}
                  </span>
                  <span className={`badge ${BADGE_CLASS[evt.event_type] || ''}`}>
                    {formatEventType(evt.event_type)}
                  </span>
                </div>
                <div style={{ marginTop: 4, fontWeight: 500 }}>
                  {String(evt.summary)}
                </div>
                {evt.tool_name && (
                  <span style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>
                    Tool: {String(evt.tool_name)}
                    {evt.device && ` | Device: ${String(evt.device)}`}
                    {evt.devices && evt.devices.length > 0 && !evt.device && ` | Devices: ${evt.devices.join(', ')}`}
                  </span>
                )}
                {expanded === evt.id && evt.details && (
                  <pre style={{ marginTop: 8, fontSize: '0.75rem' }}>
                    {JSON.stringify(evt.details, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

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
