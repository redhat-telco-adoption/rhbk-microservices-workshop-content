import { useEffect, useState } from 'react';
import type { User } from 'oidc-client-ts';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionToggle,
  Button,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import type { RuntimeConfig } from './config';
import { accessToken, currentUser, loginPopup, logoutPopup, restoreMemoryUser, subscribe, configureSpaAuth } from './auth';
import { nextServerSessionActive } from './server-session-state.mjs';

interface ApiResult { status: number; body: unknown; }

const strategyDetails = {
  spa: {
    title: 'Public SPA',
    summary: 'The browser signs in with Keycloak and sends an access token directly to the Orders API.',
    diagramLabel: 'Public SPA sign-in and API request flow',
    diagramNote: 'The popup returns the authorization result. The original page exchanges the code and keeps the resulting tokens in memory for API requests.',
    flows: [
      { label: 'Sign in', nodes: ['Browser app', 'Keycloak', 'Browser session'], connectors: ['Authorization code + PKCE', 'Tokens held in memory'] },
      { label: 'Load orders', nodes: ['Browser app', 'Orders API'], connectors: ['Bearer access token'] },
    ],
    strengths: ['No server-side login session is needed for the UI.', 'The browser calls the API directly.'],
    tradeoffs: ['JavaScript can access the short-lived token while the app is open.', 'The API must allow the SPA origin and validate the token.'],
    caveat: 'This demo keeps tokens in memory. Reloading the page clears the session; never store access tokens in browser storage.',
    session: 'The browser completes the authorization-code flow with PKCE. The access token stays in memory and is sent to the API as a bearer token.',
  },
  bff: {
    title: 'Backend for frontend (BFF)',
    summary: 'A server signs in with Keycloak, keeps OAuth tokens, and calls the Orders API for the browser.',
    diagramLabel: 'BFF sign-in and API request flow',
    diagramNote: 'After the callback, the BFF gives the browser an HttpOnly session cookie. OAuth tokens remain in the BFF session.',
    flows: [
      { label: 'Sign in', nodes: ['Browser', 'Keycloak', 'BFF'], connectors: ['Login redirect', 'Callback + code exchange'] },
      { label: 'Load orders', nodes: ['Browser', 'BFF', 'Orders API'], connectors: ['Session cookie', 'Bearer access token'] },
    ],
    strengths: ['OAuth tokens stay on the server instead of in browser JavaScript.', 'The browser calls same-origin endpoints.'],
    tradeoffs: ['The BFF must protect cookie-authenticated writes against CSRF.', 'The server needs a reliable session and authorized-client store.'],
    caveat: 'This workshop stores sessions in pod memory. A restart signs users out; production needs shared, durable session storage.',
    session: 'The BFF keeps OAuth tokens in its server-side session. The browser receives an HttpOnly session cookie and a separate CSRF token for write requests.',
  },
  proxy: {
    title: 'Reverse proxy with oauth2-proxy',
    summary: 'A gateway checks the browser session and adds an access token before forwarding API requests.',
    diagramLabel: 'Reverse proxy sign-in and API request flow',
    diagramNote: 'NGINX asks oauth2-proxy to validate the session on each request. oauth2-proxy stores encrypted session data in Redis; the browser only keeps an opaque HttpOnly cookie.',
    flows: [
      { label: 'Sign in', nodes: ['Browser', 'Keycloak', 'oauth2-proxy'], connectors: ['Login redirect', 'Callback + code exchange'] },
      { label: 'Load orders', nodes: ['Browser', 'NGINX gateway', 'Orders API'], connectors: ['Opaque session cookie', 'Auth check + bearer token'] },
    ],
    strengths: ['OAuth tokens stay behind the gateway and are never returned to the browser.', 'The gateway can protect an existing API without adding login code to it.'],
    tradeoffs: ['The gateway and auth sidecar add operational components.', 'Cookie-authenticated writes need an explicit CSRF check.'],
    caveat: 'This demo uses an ephemeral Redis session store, so pod replacement signs users out. Sign out also ends the Keycloak session.',
    session: 'The gateway keeps OAuth tokens in a server-side session. The browser receives an opaque HttpOnly cookie; the gateway checks it before forwarding API requests.',
  },
} as const;

function readCookieNames(): string[] {
  return document.cookie.split(';').map((part) => part.trim().split('=', 1)[0]).filter(Boolean);
}

function accessClaims(user: User | null) {
  if (!user?.access_token) return null;
  try {
    const payload = user.access_token.split('.')[1];
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(normalized)) as Record<string, unknown>;
    const roles = (claims.realm_access as { roles?: unknown[] } | undefined)?.roles ?? [];
    return {
      sub: typeof claims.sub === 'string' ? claims.sub : null,
      username: typeof claims.preferred_username === 'string' ? claims.preferred_username : null,
      roles: Array.isArray(roles) ? roles.filter((role): role is string => typeof role === 'string') : [],
      // A single audience arrives as a string, several as an array.
      aud: (Array.isArray(claims.aud) ? claims.aud : [claims.aud]).filter((item): item is string => typeof item === 'string'),
      exp: typeof claims.exp === 'number' ? claims.exp : null,
    };
  } catch { return null; }
}

export function App({ config }: { config: RuntimeConfig }) {
  const [user, setUser] = useState<User | null>(currentUser());
  const [serverSessionActive, setServerSessionActive] = useState(false);
  const [serverSessionChecked, setServerSessionChecked] = useState(config.authMode === 'spa');
  const [expandedDetails, setExpandedDetails] = useState({ sessionStorage: false, tokenClaims: false });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<ApiResult | null>(null);
  const [csrf, setCsrf] = useState('');
  const [messageType, setMessageType] = useState<'info' | 'success' | 'danger'>('info');

  useEffect(() => {
    if (config.authMode === 'spa') {
      configureSpaAuth(config);
      void restoreMemoryUser();
    }
    void fetch('/csrf', { credentials: 'same-origin', cache: 'no-store' }).then(async (response) => {
      const data = await response.json().catch(() => ({})) as { token?: string };
      if (typeof data.token === 'string') setCsrf(data.token);
      else setCsrf(readCookieNames().includes('XSRF-TOKEN') ? cookieValue('XSRF-TOKEN') : '');
    }).catch(() => undefined);
    if (config.authMode !== 'spa') {
      void fetch('/api/orders', { credentials: 'same-origin', cache: 'no-store' })
        .then((response) => setServerSessionActive(response.ok))
        .catch(() => setServerSessionActive(false))
        .finally(() => setServerSessionChecked(true));
    }
    const unlisten = config.authMode === 'spa' ? subscribe(setUser) : () => undefined;
    return unlisten;
  }, [config]);

  const credentials: RequestCredentials = config.authMode === 'spa' ? 'omit' : 'same-origin';
  const csrfHeader = config.authMode === 'proxy' ? 'X-Workshop-CSRF' : 'X-XSRF-TOKEN';
  const csrfValue = config.authMode === 'proxy' ? '1' : csrf;

  async function apiRequest(path: string, init: RequestInit = {}): Promise<ApiResult> {
    const headers = new Headers(init.headers);
    if (init.body) headers.set('Content-Type', 'application/json');
    if (config.authMode !== 'spa' && init.method && init.method !== 'GET' && init.method !== 'HEAD') headers.set(csrfHeader, csrfValue);
    if (config.authMode === 'spa') {
      const token = await accessToken();
      if (!token) throw new Error('Sign in before using the APIs.');
      headers.set('Authorization', `Bearer ${token}`);
    }
    let url = path;
    if (config.authMode === 'spa') {
      if (path.startsWith('/api/legacy/')) {
        url = `${config.legacyBaseUrl.replace(/\/$/, '')}${path.slice(4)}`;
      } else {
        url = `${config.ordersBaseUrl.replace(/\/$/, '')}${path.replace(/^\/api/, '')}`;
      }
    }
    const response = await fetch(url, { ...init, headers, credentials, cache: 'no-store' });
    const body = await response.json().catch(() => ({ error: 'invalid_response' }));
    return { status: response.status, body };
  }

  async function run(name: string, path: string, init?: RequestInit) {
    setBusy(true); setMessage(''); setResult(null); setMessageType('info');
    try {
      const response = await apiRequest(path, init);
      setResult(response);
      if (config.authMode !== 'spa') {
        setServerSessionActive((active) => nextServerSessionActive(active, response.status));
      }
      setMessage(response.status >= 200 && response.status < 300 ? `${name} completed.` : `${name} returned HTTP ${response.status}.`);
      setMessageType(response.status >= 200 && response.status < 300 ? 'success' : 'danger');
      if (response.status === 401 && config.authMode !== 'spa') setMessage('Your session is not signed in. Select Sign in and try again.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request could not be completed.');
      setMessageType('danger');
    } finally { setBusy(false); }
  }

  async function signIn() {
    setMessage(''); setMessageType('info');
    if (config.authMode === 'spa') {
      try { setBusy(true); await loginPopup(); setMessage('Signed in with a short-lived in-memory session.'); setMessageType('success'); }
      catch (error) { setMessage(error instanceof Error ? error.message : 'Sign-in failed.'); setMessageType('danger'); }
      finally { setBusy(false); }
    } else if (config.authMode === 'bff') {
      window.location.assign('/oauth2/authorization/keycloak');
    } else {
      window.location.assign('/oauth2/start?rd=%2F');
    }
  }

  async function signOut() {
    setBusy(true); setMessage(''); setMessageType('info');
    try {
      if (config.authMode === 'spa') await logoutPopup();
      else if (config.authMode === 'bff') {
        const form = document.createElement('form');
        form.method = 'POST'; form.action = '/logout';
        const token = document.createElement('input');
        token.type = 'hidden'; token.name = '_csrf'; token.value = csrfValue;
        form.append(token); document.body.append(form); form.submit();
        return;
      }
      else {
        const headers = new Headers({ [csrfHeader]: csrfValue });
        // The sign-out response redirects; following it would hit Keycloak and be blocked by CSP.
        await fetch('/logout', { method: 'POST', headers, credentials: 'same-origin', cache: 'no-store', redirect: 'manual' });
      }
      setResult(null); setMessage('Signed out.'); setMessageType('success');
      if (config.authMode !== 'spa') window.location.assign('/');
    } catch { setMessage('Sign-out could not be completed. Try again.'); setMessageType('danger'); }
    finally { setBusy(false); }
  }

  const claims = config.authMode === 'spa' ? accessClaims(user) : null;
  const memoryToken = config.authMode === 'spa' && Boolean(user?.access_token);
  const strategy = strategyDetails[config.authMode];
  const sessionActive = config.authMode === 'spa' ? Boolean(user) : serverSessionActive;

  return <main className="shell">
    <Masthead className="app-masthead" display={{ default: 'stack', lg: 'inline' }}>
      <MastheadMain>
        <MastheadBrand>
          <MastheadLogo component="div">
            <div className="masthead-copy">
              <p className="eyebrow">Red Hat build of Keycloak · Security workshop</p>
              <h1>Orders console</h1>
              <p>Compare where OAuth tokens are held and how each pattern sends API requests.</p>
            </div>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar className="masthead-toolbar" aria-label="Session actions">
          <ToolbarContent>
            <ToolbarItem><span className="mode-label">{strategy.title}</span></ToolbarItem>
            <ToolbarItem><Button variant={sessionActive ? 'secondary' : 'primary'} onClick={() => void (sessionActive ? signOut() : signIn())} isDisabled={busy || (config.authMode !== 'spa' && !serverSessionChecked)}>{busy ? 'Working…' : sessionActive ? 'Sign out' : 'Sign in'}</Button></ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>

    <section className="strategy-panel" aria-labelledby="strategy-heading">
      <div className="strategy-intro">
        <p className="section-kicker">Authentication strategy</p>
        <h2 id="strategy-heading">{strategy.title}</h2>
        <p>{strategy.summary}</p>
      </div>
      <figure className="strategy-diagram" aria-label={strategy.diagramLabel}>
        <figcaption>What happens</figcaption>
        {strategy.flows.map((flow) => <div className="flow-row" key={flow.label}>
          <span className="flow-label">{flow.label}</span>
          <ol className="flow-nodes">
            {flow.nodes.map((node, index) => <li className="flow-step" key={node}>
              <span className="flow-node">{node}</span>
              {index < flow.connectors.length && <span className="flow-connector"><span aria-hidden="true">→</span><small>{flow.connectors[index]}</small></span>}
            </li>)}
          </ol>
        </div>)}
        <p className="diagram-note">{strategy.diagramNote}</p>
      </figure>
      <div className="strategy-points">
        <section aria-labelledby="strengths-heading"><h3 id="strengths-heading">Why use this approach</h3><ul>{strategy.strengths.map((item) => <li key={item}>{item}</li>)}</ul></section>
        <section aria-labelledby="tradeoffs-heading"><h3 id="tradeoffs-heading">Tradeoffs</h3><ul>{strategy.tradeoffs.map((item) => <li key={item}>{item}</li>)}</ul></section>
      </div>
      <p className="strategy-caveat"><strong>Workshop caveat:</strong> {strategy.caveat}</p>
    </section>

    <div className="workspace">
    <section className="panel" aria-labelledby="session-heading">
      <div className="panel-heading">
        <div><p className="section-kicker">Your sign-in</p><h2 id="session-heading">Session details</h2></div>
      </div>
      <p className="panel-intro">{config.authMode === 'spa' ? (user ? `You are signed in as ${claims?.username ?? 'a workshop user'}.` : 'You are not signed in. Use Sign in in the page header to start.') : 'Your browser session is handled by the server-side sign-in flow.'}</p>
      <p className="session-explanation">{strategy.session}</p>
      <Accordion className="session-details" aria-label="Technical session and identity details" headingLevel="h3" asDefinitionList={false}>
        <AccordionItem isExpanded={expandedDetails.sessionStorage}>
          <AccordionToggle id="session-storage-toggle" aria-controls="session-storage-content" onClick={() => setExpandedDetails((current) => ({ ...current, sessionStorage: !current.sessionStorage }))}>Where session data is stored</AccordionToggle>
          <AccordionContent id="session-storage-content" aria-labelledby="session-storage-toggle">
            <dl className="facts">
              <div><dt>Cookies readable by JavaScript</dt><dd>{readCookieNames().join(', ') || 'None'}</dd></div>
              <div><dt>Session cookie</dt><dd>{config.authMode === 'spa' ? 'This sign-in flow does not use an app session cookie.' : 'HttpOnly; JavaScript cannot read it.'}</dd></div>
              <div><dt>Access token in JavaScript memory</dt><dd>{memoryToken ? 'Yes, while this SPA session is active.' : 'No'}</dd></div>
            </dl>
          </AccordionContent>
        </AccordionItem>
        {claims && <AccordionItem isExpanded={expandedDetails.tokenClaims}>
          <AccordionToggle id="token-claims-toggle" aria-controls="token-claims-content" onClick={() => setExpandedDetails((current) => ({ ...current, tokenClaims: !current.tokenClaims }))}>Identity and access details</AccordionToggle>
          <AccordionContent id="token-claims-content" aria-labelledby="token-claims-toggle">
            <p className="detail-help">A token is a signed, short-lived credential. These display fields help explain what the Orders API checks; the API validates the token independently.</p>
            <dl className="facts">
              <div><dt>Username</dt><dd>{claims.username ?? 'Unavailable'}</dd></div>
              <div><dt>Workshop roles</dt><dd>{claims.roles.map((role) => role === 'manager' ? 'Manager' : role === 'user' ? 'User' : role).join(', ') || 'None'}</dd></div>
              <div><dt>Intended APIs</dt><dd>{claims.aud.map((audience) => audience === 'orders-api' ? 'Orders API' : audience === 'legacy-api' ? 'Legacy API' : audience).join(', ') || 'None'}</dd></div>
              <div><dt>Access expires</dt><dd>{claims.exp ? new Date(claims.exp * 1000).toLocaleString() : 'Unavailable'}</dd></div>
              <div><dt>Subject identifier</dt><dd>{claims.sub ?? 'Unavailable'}</dd></div>
            </dl>
          </AccordionContent>
        </AccordionItem>}
      </Accordion>
    </section>

    <section className="panel" aria-labelledby="orders-heading">
      <div className="panel-heading">
        <div><p className="section-kicker">Try the API</p><h2 id="orders-heading">Orders</h2></div>
      </div>
      <p className="panel-intro">View shared demonstration orders or create one sample widget order.</p>
      <div className="actions">
        <Button variant="primary" onClick={() => void run('Order lookup', '/api/orders') } isDisabled={busy}>{busy ? 'Working…' : 'View orders'}</Button>
        <Button variant="secondary" onClick={() => void run('Order creation', '/api/orders', { method: 'POST', body: JSON.stringify({ item: 'widget', quantity: 1 }) })} isDisabled={busy}>Create a sample order</Button>
      </div>
      {config.legacyEnabled ? <div className="actions legacy-actions"><Button variant="link" onClick={() => void run('Legacy customer lookup', '/api/legacy/customers')} isDisabled={busy}>View legacy customers</Button></div> : <p className="muted">Legacy customer data is not connected in this deployment.</p>}
      {message && <p role="status" aria-live="polite" className={`status status-${messageType}`}>{message}</p>}
      {result && <div className="response-block"><h3>API response <span>HTTP {result.status}</span></h3><pre className="result" role="region" tabIndex={0} aria-label="API response">{JSON.stringify(result.body, null, 2)}</pre></div>}
    </section>
    </div>

  </main>;
}

function cookieValue(name: string) {
  const value = document.cookie.split(';').map((entry) => entry.trim()).find((entry) => entry.startsWith(`${name}=`));
  return value ? decodeURIComponent(value.slice(name.length + 1)) : '';
}
