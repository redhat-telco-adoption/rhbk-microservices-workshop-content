import { UserManager, WebStorageStateStore, InMemoryWebStorage, type User } from 'oidc-client-ts';
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
    scope: 'openid profile email',
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
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
  const expiry = user.expires_at ?? 0;
  if (expiry * 1000 - Date.now() < 30_000) {
    const refreshed = await refresh();
    return refreshed?.access_token ?? null;
  }
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

