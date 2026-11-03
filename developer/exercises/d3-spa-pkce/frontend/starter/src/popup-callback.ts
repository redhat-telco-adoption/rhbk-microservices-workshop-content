import { InMemoryWebStorage, UserManager, WebStorageStateStore } from 'oidc-client-ts';
import { loadRuntimeConfig } from './config';

async function notifyOpener() {
  const config = await loadRuntimeConfig();
  if (config.authMode !== 'spa') throw new Error('Popup sign-in is only available in SPA mode.');

  // This callback manager only relays the response URL. The opener's manager
  // owns the PKCE transaction and validates state before exchanging the code.
  const callbackManager = new UserManager({
    authority: config.issuer,
    client_id: config.spaClientId,
    redirect_uri: `${window.location.origin}/auth/popup-callback`,
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    stateStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: false,
    monitorSession: false,
  });
  await callbackManager.signinPopupCallback(window.location.href);
}

void notifyOpener().catch(() => {
  document.body.textContent = 'Sign-in could not be completed. Return to the app and try again.';
});
