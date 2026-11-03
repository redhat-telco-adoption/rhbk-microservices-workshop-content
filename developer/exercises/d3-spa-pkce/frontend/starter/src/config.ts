/** Public, non-secret configuration fetched with no-store before React mounts. */
export interface RuntimeConfig {
  authMode: 'bff' | 'spa' | 'proxy';
  issuer: string;
  spaClientId: string;
  ordersBaseUrl: string;
  legacyBaseUrl: string;
  legacyEnabled: boolean;
}

export async function loadRuntimeConfig(): Promise<RuntimeConfig> {
  const response = await fetch('/config.json', { cache: 'no-store', credentials: 'same-origin' });
  if (!response.ok) throw new Error('The public application configuration is unavailable.');
  const value = await response.json() as RuntimeConfig;
  if (!['bff', 'spa', 'proxy'].includes(value.authMode) ||
      typeof value.issuer !== 'string' || typeof value.spaClientId !== 'string' ||
      typeof value.ordersBaseUrl !== 'string' || typeof value.legacyBaseUrl !== 'string' ||
      typeof value.legacyEnabled !== 'boolean') {
    throw new Error('The public application configuration is invalid.');
  }
  for (const endpoint of [value.issuer, value.ordersBaseUrl, value.legacyBaseUrl]) {
    if (!endpoint) continue;
    if (endpoint.startsWith('/') && value.authMode !== 'spa') continue;
    if (new URL(endpoint).protocol !== 'https:') throw new Error('Only HTTPS public endpoints are allowed.');
  }
  return value;
}
