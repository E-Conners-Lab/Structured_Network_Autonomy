import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

function jsonResponse(data, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: () => Promise.resolve(data),
  });
}

/** Default mock that returns correct shapes for all API endpoints. */
function defaultMock(url) {
  if (url.includes('/reports/compliance')) {
    return jsonResponse({
      time_window_hours: 24, total_evaluations: 0,
      permit_count: 0, escalate_count: 0, block_count: 0,
      top_escalated_tools: [], current_eas: 0.1,
    });
  }
  if (url.includes('/eas/history')) {
    return jsonResponse({ items: [], total: 0, page: 1, page_size: 20, total_pages: 1 });
  }
  if (url.includes('/eas')) {
    return jsonResponse({ eas: 0.1, timestamp: new Date().toISOString() });
  }
  if (url.includes('/escalation')) {
    return jsonResponse({ items: [], total: 0, page: 1, page_size: 50, total_pages: 1 });
  }
  if (url.includes('/agents')) {
    return jsonResponse({ items: [], total: 0, page: 1, page_size: 50, total_pages: 1 });
  }
  if (url.includes('/health')) {
    return jsonResponse({ status: 'ok', eas: 0.1, policy_loaded: true, policy_version: '1.0', db_connected: true });
  }
  return jsonResponse({ items: [], total: 0, page: 1, page_size: 25, total_pages: 1 });
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe('App', () => {
  it('shows login form when no API key', () => {
    render(<App />);
    expect(screen.getByPlaceholderText('API Key')).toBeInTheDocument();
    expect(screen.getByText('Enter your SNA API key to access the dashboard.')).toBeInTheDocument();
  });

  it('shows dashboard after login', async () => {
    mockFetch.mockImplementation((url) => {
      if (url.includes('/reports/compliance')) {
        return jsonResponse({
          time_window_hours: 24,
          total_evaluations: 10,
          permit_count: 7,
          escalate_count: 2,
          block_count: 1,
          top_escalated_tools: [],
          current_eas: 0.5,
        });
      }
      return defaultMock(url);
    });

    render(<App />);

    const input = screen.getByPlaceholderText('API Key');
    fireEvent.change(input, { target: { value: 'test-key' } });
    fireEvent.click(screen.getByText('Login'));

    await waitFor(() => {
      expect(screen.getByText('Overview')).toBeInTheDocument();
      expect(screen.getByText('Escalations')).toBeInTheDocument();
      expect(screen.getByText('Audit Log')).toBeInTheDocument();
      expect(screen.getByText('Agents')).toBeInTheDocument();
    });
  });

  it('stores API key in sessionStorage', () => {
    render(<App />);
    const input = screen.getByPlaceholderText('API Key');
    fireEvent.change(input, { target: { value: 'my-secret-key' } });
    fireEvent.click(screen.getByText('Login'));
    expect(sessionStorage.getItem('sna_api_key')).toBe('my-secret-key');
  });

  it('clears API key on logout', async () => {
    sessionStorage.setItem('sna_api_key', 'existing-key');
    mockFetch.mockImplementation(defaultMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Logout')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Logout'));
    expect(sessionStorage.getItem('sna_api_key')).toBeNull();
  });

  it('sends Authorization header on API calls', async () => {
    sessionStorage.setItem('sna_api_key', 'bearer-test');
    mockFetch.mockImplementation(defaultMock);

    render(<App />);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    const calls = mockFetch.mock.calls;
    const hasAuth = calls.some(([, opts]) =>
      opts?.headers?.Authorization === 'Bearer bearer-test'
    );
    expect(hasAuth).toBe(true);
  });

  it('switches tabs', async () => {
    sessionStorage.setItem('sna_api_key', 'test');
    mockFetch.mockImplementation(defaultMock);

    render(<App />);

    // Click EAS tab
    await waitFor(() => {
      expect(screen.getByText('EAS')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('EAS'));

    await waitFor(() => {
      expect(screen.getByText('Manual EAS Adjustment (Admin)')).toBeInTheDocument();
    });
  });

  it('renders all tab names', async () => {
    sessionStorage.setItem('sna_api_key', 'test');
    mockFetch.mockImplementation(defaultMock);

    render(<App />);

    await waitFor(() => {
      ['Overview', 'Escalations', 'Audit Log', 'Agents', 'EAS', 'Policy'].forEach((name) => {
        expect(screen.getByText(name)).toBeInTheDocument();
      });
    });
  });
});
