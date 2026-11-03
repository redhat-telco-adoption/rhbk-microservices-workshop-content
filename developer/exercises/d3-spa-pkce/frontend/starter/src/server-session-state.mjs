/** Keep server-session controls stable across authorization denials and service errors. */
export function nextServerSessionActive(active, status) {
  if (status >= 200 && status < 300) return true;
  if (status === 401) return false;
  return active;
}
