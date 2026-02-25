/**
 * Fetch wrapper for the SNA API.
 * Reads Bearer token from sessionStorage and attaches it to every request.
 */

const API_KEY_STORAGE = 'sna_api_key';

export function getApiKey() {
  return sessionStorage.getItem(API_KEY_STORAGE) || '';
}

export function setApiKey(key) {
  sessionStorage.setItem(API_KEY_STORAGE, key);
}

export function clearApiKey() {
  sessionStorage.removeItem(API_KEY_STORAGE);
}

/**
 * Fetch from the SNA API with automatic Bearer token and JSON handling.
 * @param {string} path - API path (e.g. "/audit")
 * @param {object} options - fetch options (method, body, etc.)
 * @returns {Promise<{ok: boolean, status: number, data: any}>}
 */
export async function apiFetch(path, options = {}) {
  const key = getApiKey();
  const headers = {
    'Content-Type': 'application/json',
    ...(key ? { Authorization: `Bearer ${key}` } : {}),
    ...(options.headers || {}),
  };

  const response = await fetch(path, {
    ...options,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let data = null;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    data = await response.json();
  }

  return { ok: response.ok, status: response.status, data };
}
