import express from 'express';
import pino from 'pino';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';
import { trace } from '@opentelemetry/api';

const app = express();
const logger = pino({
  base: { service: 'notifications-api' },
  timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,
  formatters: { level: (label) => ({ level: label.toUpperCase() }) },
});
const port = Number(process.env.PORT ?? 8080);
const issuer = process.env.ISSUER;
if (!issuer) throw new Error('ISSUER is required');
const jwks = createRemoteJWKSet(new URL(`${issuer.replace(/\/$/, '')}/protocol/openid-connect/certs`), {
  timeoutDuration: 3000,
  cooldownDuration: 30000,
  cacheMaxAge: 300000,
});
app.disable('x-powered-by');

app.use((req, res, next) => {
  req.requestId = randomUUID();
  const spanContext = trace.getActiveSpan()?.spanContext();
  req.traceId = spanContext?.traceId ?? req.get('traceparent')?.match(/^[\da-f]{2}-([\da-f]{32})-/i)?.[1] ?? null;
  req.spanId = spanContext?.spanId ?? null;
  res.on('finish', () => {
    const claims = req.authClaims;
    const fields = {
      event: res.statusCode === 202 && req.path === '/notify' ? 'notification_sent' : 'request_completed',
      request_id: req.requestId,
      trace_id: req.traceId,
      span_id: req.spanId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      decision: res.statusCode >= 400 ? 'deny' : 'allow',
      reason: req.authReason ?? null,
      subject: claims?.sub ?? null,
      username: claims?.preferred_username ?? null,
      client_id: claims?.azp ?? null,
      roles: claims?.resource_access?.['notifications-api']?.roles ?? [],
    };
    logger[res.statusCode >= 400 ? 'warn' : 'info'](fields, fields.event);
  });
  next();
});
app.use(express.json({ limit: '16kb', strict: true }));

app.get('/health/live', (_req, res) => res.status(200).json({ status: 'ok' }));
app.get('/health/ready', (_req, res) => res.status(200).json({ status: 'ok' }));

function bearer(req) {
  const value = req.get('authorization');
  if (!value || !/^Bearer\s+\S+$/i.test(value)) return null;
  return value.replace(/^Bearer\s+/i, '');
}

app.post('/notify', async (req, res) => {
  let status = 202;
  let reason = null;
  let claims = null;
  try {
    const token = bearer(req);
    if (!token) {
      status = 401;
      reason = 'missing_token';
    } else {
      try {
        // ANTI-PATTERN: any published algorithm, any audience, any issuer. Exercise D4: pass
        // the issuer, the 'notifications-api' audience, and an RS256-only algorithm list.
        const verified = await jwtVerify(token, jwks, {
          clockTolerance: 30,
        });
        claims = verified.payload;
        if (claims.typ !== 'Bearer' || !claims.exp || !claims.sub) {
          status = 401;
          reason = 'invalid_token';
          claims = null;
        } else if (claims.azp !== 'orders-api') {
          status = 403;
          reason = 'wrong_client';
        } else if (!claims.resource_access?.['notifications-api']?.roles?.includes('notifier')) {
          status = 403;
          reason = 'missing_role';
        }
      } catch (error) {
        status = 401;
        reason = error?.code === 'ERR_JWT_EXPIRED' ? 'expired' :
          error?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && error.claim === 'iss' ? 'bad_issuer' :
          error?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && error.claim === 'aud' ? 'bad_audience' : 'invalid_token';
      }
    }
  } catch {
    status = 401;
    reason = 'invalid_token';
  }

  req.authClaims = claims;
  req.authReason = reason;
  if (status === 401) res.set('WWW-Authenticate', 'Bearer');
  if (status !== 202) return res.status(status).json({ error: status === 401 ? 'unauthorized' : 'forbidden' });
  return res.status(202).json({ accepted: true });
});

app.use((_err, req, res, _next) => {
  req.authReason = 'invalid_request';
  return res.status(400).json({ error: 'bad_request' });
});
app.listen(port, '0.0.0.0', () => logger.info({ event: 'server_started', port }));
