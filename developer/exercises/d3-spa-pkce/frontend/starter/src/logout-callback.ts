import { InMemoryWebStorage, UserManager, WebStorageStateStore } from 'oidc-client-ts';
import { loadRuntimeConfig } from './config';

async function notifyOpener() {
  const config = await loadRuntimeConfig();
  if (config.authMode !== 'spa') throw new Error('Popup sign-out is only available in SPA mode.');

  const callbackManager = new UserManager({
    authority: config.issuer,
    client_id: config.spaClientId,
    redirect_uri: `${window.location.origin}/auth/popup-callback`,
    popup_redirect_uri: `${window.location.origin}/auth/popup-callback`,
    post_logout_redirect_uri: `${window.location.origin}/auth/logout-callback`,
    popup_post_logout_redirect_uri: `${window.location.origin}/auth/logout-callback`,
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: false,
    monitorSession: false,
  });
  await callbackManager.signoutPopupCallback(window.location.href);
}

void notifyOpener().catch(() => {
  document.body.textContent = 'Sign-out could not be completed. Return to the app and try again.';
});
