import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../hooks/useApi';

const POLL_INTERVAL = 30000;

const PLATFORM_LABELS = {
  cisco_iosxe: 'IOS-XE',
  cisco_nxos: 'NX-OS',
  arista_eos: 'EOS',
  juniper_junos: 'JunOS',
};

function StatusDot({ status }) {
  const color =
    status === 'reachable'
      ? 'var(--success)'
      : status === 'unreachable'
        ? 'var(--danger)'
        : 'var(--warning)';
  return (
    <span
      style={{
        display: 'inline-block',
        width: 10,
        height: 10,
        borderRadius: '50%',
        background: color,
        marginRight: 6,
      }}
    />
  );
}

export default function DeviceGrid() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    const res = await apiFetch('/devices/status');
    if (res.ok) {
      setDevices(res.data.devices || []);
      setError(null);
    } else if (res.status === 401 || res.status === 403) {
      setError('Authentication required.');
    } else {
      setError('Failed to load device status.');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [load]);

  function handleRefresh() {
    setLoading(true);
    load();
  }

  if (error) {
    return <div className="empty">{error}</div>;
  }

  const reachable = devices.filter((d) => d.status === 'reachable').length;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <span style={{ color: 'var(--muted)', fontSize: '0.875rem' }}>
          {devices.length} devices &middot; {reachable} reachable
        </span>
        <button className="btn btn-sm" onClick={handleRefresh} disabled={loading}>
          {loading ? 'Checking…' : 'Refresh'}
        </button>
      </div>

      <div className="grid">
        {devices.map((d) => (
          <div className="card" key={d.name}>
            <h3>{d.name}</h3>
            <div style={{ marginBottom: 8 }}>
              <StatusDot status={loading ? 'loading' : d.status} />
              <span style={{ fontSize: '0.875rem' }}>
                {loading ? 'checking…' : d.status}
              </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--muted)', marginBottom: 6 }}>
              {d.host}
            </div>
            <span className={`badge badge-${d.status === 'reachable' ? 'active' : 'suspended'}`}>
              {PLATFORM_LABELS[d.platform] || d.platform}
            </span>
          </div>
        ))}
      </div>

      {!loading && devices.length === 0 && (
        <div className="empty">No devices in inventory.</div>
      )}
    </div>
  );
}
