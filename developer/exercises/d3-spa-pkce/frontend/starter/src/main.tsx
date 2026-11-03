import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { loadRuntimeConfig } from './config';
import '@patternfly/react-core/dist/styles/base.css';
import './style.css';

async function start() {
  const root = createRoot(document.getElementById('root')!);
  try {
    const config = await loadRuntimeConfig();
    root.render(<React.StrictMode><App config={config} /></React.StrictMode>);
  } catch {
    root.render(<main className="error"><h1>Application unavailable</h1><p>Public configuration could not be loaded securely.</p></main>);
  }
}
void start();
