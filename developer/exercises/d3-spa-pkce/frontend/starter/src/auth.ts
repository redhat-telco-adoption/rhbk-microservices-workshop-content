import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts';
import type { RuntimeConfig } from './config';

let manager: UserManager | undefined;
let user: User | null = null;
let pendingRefresh: Promise<User | null> | null = null;
const listeners = new Set<(current: User | null) => void>();

function notify() { listeners.forEach((listener) => listener(user)); }

export function configureSpaAuth(config: RuntimeConfig): UserManager {
  if (manager) return manager;
  const origin = window.location.origin;
  manager = new UserManager({
    authority: config.issuer,
    client_id: config.spaClientId,
    redirect_uri: `${origin}/auth/popup-callback`,
    popup_redirect_uri: `${origin}/auth/popup-callback`,
    post_logout_redirect_uri: `${origin}/auth/logout-callback`,
    popup_post_logout_redirect_uri: `${origin}/auth/logout-callback`,
    response_type: 'code',
    // ANTI-PATTERN: sends no code_challenge, so a stolen authorization code can be redeemed.
    // Exercise D3: remove this line; oidc-client-ts then uses PKCE (S256) for every sign-in.
    disablePKCE: true,
    scope: 'openid profile email',
    // ANTI-PATTERN: localStorage outlives the tab and any script on the origin can read it.
    // Exercise D3: keep the user and the sign-in state in an InMemoryWebStorage instead.
    userStore: new WebStorageStateStore({ store: window.localStorage }),
    stateStore: new WebStorageStateStore({ store: window.localStorage }),
    automaticSilentRenew: false,
    monitorSession: false,
    loadUserInfo: false,
    popupWindowFeatures: { popup: true, width: 520, height: 680, left: 100, top: 100 },
  });
  manager.events.addUserLoaded((loaded) => { user = loaded; notify(); });
  manager.events.addUserUnloaded(() => { user = null; notify(); });
  manager.events.addAccessTokenExpired(() => { void refresh(); });
  return manager;
}

export function currentUser() { return user; }
export function subscribe(listener: (current: User | null) => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export async function restoreMemoryUser() {
  if (!manager) return;
  user = await manager.getUser();
  notify();
  if (user?.expired) await refresh();
}

export async function loginPopup() {
  if (!manager) throw new Error('Sign-in is not configured.');
  try {
    user = await manager.signinPopup();
    notify();
  } catch (error) {
    const text = error instanceof Error ? error.message : '';
    if (text.toLowerCase().includes('popup') || text.toLowerCase().includes('blocked')) {
      throw new Error('The sign-in popup was blocked. Allow popups for this site, then select Sign in again.');
    }
    throw new Error('Sign-in did not complete. Close the popup and try again.');
  }
}

export async function accessToken(): Promise<string | null> {
  if (!manager || !user) return null;
  // ANTI-PATTERN: returns the token even after it expires, so API calls start failing with 401.
  // Exercise D3: when it expires within 30 seconds, refresh() first and return the new token.
  return user.access_token;
}

async function refresh(): Promise<User | null> {
  if (!manager || !user) return null;
  if (pendingRefresh) return pendingRefresh;
  pendingRefresh = manager.signinSilent().then((updated) => {
    user = updated;
    notify();
    return updated;
  }).catch(async () => {
    user = null;
    await manager?.removeUser();
    notify();
    return null;
  }).finally(() => { pendingRefresh = null; });
  return pendingRefresh;
}

export async function logoutPopup() {
  if (!manager) return;
  try {
    await manager.signoutPopup();
  } finally {
    user = null;
    await manager.removeUser();
    notify();
  }
}

