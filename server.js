'use strict';
/**
 * Makana public remote MCP server.
 * -----------------------------------------------------------------------------
 * Turns the local stdio proxy into a PUBLIC, hosted MCP server that Claude
 * connects to as a normal remote/custom connector (a "Web" connector).
 *
 * It plays two roles at once:
 *   1) MCP resource server  — serves Streamable-HTTP MCP at POST /mcp, validates
 *      the bearer token Claude sends, and forwards each JSON-RPC message to the
 *      Salesforce custom MCP endpoint with that user's Salesforce access token.
 *   2) OAuth 2.1 bridge     — Claude authenticates against THIS server (it can't
 *      talk to Salesforce's OAuth directly: the SF MCP endpoint returns a bare
 *      401 with no WWW-Authenticate, and Salesforce needs the connected-app
 *      client_secret Claude doesn't hold). So this server exposes the discovery
 *      docs + /authorize + /token, and internally runs the real OAuth (PKCE)
 *      against Salesforce / Experience Cloud, mapping Claude's token -> the SF
 *      token behind the scenes.
 *
 * State is in-memory (single dyno, demo-grade): a restart forces re-auth.
 *
 * Required env:
 *   SF_MCP_URL            the Salesforce custom MCP server URL
 *   SF_MCP_CLIENT_ID      connected app consumer key
 *   SF_MCP_CLIENT_SECRET  connected app consumer secret
 * Optional env:
 *   SF_AUTHORIZE_URL      default https://login.salesforce.com/services/oauth2/authorize
 *                         (set to the Experience Cloud community endpoint for patient login)
 *   SF_TOKEN_URL          default https://login.salesforce.com/services/oauth2/token
 *   SF_SCOPE              default "mcp_api refresh_token"
 *   PUBLIC_URL            override the externally-visible base url (else derived from the request)
 *   PORT                  Heroku sets this
 *   DEBUG                 "1" to log
 */

const express = require('express');
const crypto = require('crypto');

const SF_MCP_URL = process.env.SF_MCP_URL;
const SF_CLIENT_ID = process.env.SF_MCP_CLIENT_ID;
const SF_CLIENT_SECRET = process.env.SF_MCP_CLIENT_SECRET;
const SF_AUTHORIZE_URL = process.env.SF_AUTHORIZE_URL || 'https://login.salesforce.com/services/oauth2/authorize';
const SF_TOKEN_URL = process.env.SF_TOKEN_URL || 'https://login.salesforce.com/services/oauth2/token';
const SF_SCOPE = process.env.SF_SCOPE || 'mcp_api refresh_token';
const DEBUG = process.env.DEBUG === '1';
const PORT = process.env.PORT || 3000;

if (!SF_MCP_URL || !SF_CLIENT_ID || !SF_CLIENT_SECRET) {
  console.error('FATAL: missing SF_MCP_URL / SF_MCP_CLIENT_ID / SF_MCP_CLIENT_SECRET');
  process.exit(1);
}

function log(...a) { if (DEBUG) console.error('[makana-mcp]', ...a); }
function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function rand(n = 32) { return b64url(crypto.randomBytes(n)); }
function sha256(s) { return b64url(crypto.createHash('sha256').update(s).digest()); }

// ---- in-memory state (demo-grade) ------------------------------------------
const clients = new Map();        // client_id -> { redirect_uris:Set }
const pendingSf = new Map();      // sfState -> { verifier, claude:{redirect_uri,state,code_challenge,code_challenge_method,client_id} }
const authCodes = new Map();      // ourCode -> { sf, code_challenge, code_challenge_method, redirect_uri, client_id, exp }
const sessions = new Map();       // ourAccessToken -> { sfAccessToken, sfRefreshToken, sfSessionId, protocol }
const refreshMap = new Map();     // ourRefreshToken -> ourAccessToken

function baseUrl(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
  return `${proto}://${req.headers.host}`;
}

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// =====================  OAuth discovery documents  ==========================
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const b = baseUrl(req);
  res.json({
    resource: b + '/mcp',
    authorization_servers: [b],
    scopes_supported: ['mcp'],
    bearer_methods_supported: ['header'],
  });
});
// some clients probe the path-suffixed variant
app.get('/mcp/.well-known/oauth-protected-resource', (req, res) => {
  const b = baseUrl(req);
  res.json({ resource: b + '/mcp', authorization_servers: [b] });
});

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const b = baseUrl(req);
  res.json({
    issuer: b,
    authorization_endpoint: b + '/authorize',
    token_endpoint: b + '/token',
    registration_endpoint: b + '/register',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mcp'],
  });
});
// OpenID-style fallback some clients try
app.get('/.well-known/openid-configuration', (req, res) => res.redirect('/.well-known/oauth-authorization-server'));

// =====================  Dynamic Client Registration  =======================
app.post('/register', (req, res) => {
  const client_id = 'mc_' + rand(12);
  const redirect_uris = Array.isArray(req.body && req.body.redirect_uris) ? req.body.redirect_uris : [];
  clients.set(client_id, { redirect_uris: new Set(redirect_uris) });
  log('registered client', client_id, redirect_uris);
  res.status(201).json({
    client_id,
    redirect_uris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  });
});

// =====================  /authorize  (Claude -> us -> Salesforce)  ===========
app.get('/authorize', (req, res) => {
  const { redirect_uri, state, code_challenge, code_challenge_method, client_id } = req.query;
  if (!redirect_uri || !code_challenge) {
    return res.status(400).send('missing redirect_uri or code_challenge (PKCE required)');
  }
  // our own PKCE pair for the upstream Salesforce exchange
  const verifier = rand(32);
  const challenge = sha256(verifier);
  const sfState = rand(16);
  pendingSf.set(sfState, {
    verifier,
    claude: { redirect_uri, state, code_challenge, code_challenge_method: code_challenge_method || 'S256', client_id },
  });
  const b = baseUrl(req);
  const u = new URL(SF_AUTHORIZE_URL);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', SF_CLIENT_ID);
  u.searchParams.set('redirect_uri', b + '/oauth/callback');
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('scope', SF_SCOPE);
  u.searchParams.set('state', sfState);
  u.searchParams.set('resource', SF_MCP_URL);
  u.searchParams.set('prompt', 'login');
  log('authorize -> salesforce', u.toString());
  res.redirect(u.toString());
});

// Salesforce redirects the user back here after they log in.
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const pend = state && pendingSf.get(state);
  if (!pend) return res.status(400).send('unknown or expired authorization state');
  pendingSf.delete(state);
  if (error) return res.status(400).send('Salesforce authorization failed: ' + error + ' ' + (error_description || ''));

  try {
    const b = baseUrl(req);
    const tok = await sfToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: b + '/oauth/callback',
      code_verifier: pend.verifier,
      resource: SF_MCP_URL,
    });
    const ourCode = 'ac_' + rand(24);
    authCodes.set(ourCode, {
      sf: { sfAccessToken: tok.access_token, sfRefreshToken: tok.refresh_token },
      code_challenge: pend.claude.code_challenge,
      code_challenge_method: pend.claude.code_challenge_method,
      redirect_uri: pend.claude.redirect_uri,
      client_id: pend.claude.client_id,
      exp: Date.now() + 5 * 60 * 1000,
    });
    const back = new URL(pend.claude.redirect_uri);
    back.searchParams.set('code', ourCode);
    if (pend.claude.state) back.searchParams.set('state', pend.claude.state);
    log('salesforce callback ok -> redirecting to claude', back.origin + back.pathname);
    res.redirect(back.toString());
  } catch (e) {
    log('token exchange failed', e.message);
    res.status(502).send('Failed to exchange the Salesforce authorization code: ' + e.message);
  }
});

// =====================  /token  (Claude exchanges our code)  ================
app.post('/token', async (req, res) => {
  const { grant_type, code, code_verifier, refresh_token } = req.body;
  try {
    if (grant_type === 'authorization_code') {
      const rec = authCodes.get(code);
      if (!rec || rec.exp < Date.now()) return res.status(400).json({ error: 'invalid_grant' });
      authCodes.delete(code);
      if (rec.code_challenge) {
        if (!code_verifier || sha256(code_verifier) !== rec.code_challenge) {
          return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
        }
      }
      const ourToken = 'mt_' + rand(28);
      sessions.set(ourToken, { sfAccessToken: rec.sf.sfAccessToken, sfRefreshToken: rec.sf.sfRefreshToken, sfSessionId: null, protocol: '2025-06-18' });
      const ourRefresh = 'mr_' + rand(28);
      refreshMap.set(ourRefresh, ourToken);
      return res.json({ access_token: ourToken, token_type: 'Bearer', expires_in: 3600, refresh_token: ourRefresh, scope: 'mcp' });
    }
    if (grant_type === 'refresh_token') {
      const ourToken = refreshMap.get(refresh_token);
      const sess = ourToken && sessions.get(ourToken);
      if (!sess) return res.status(400).json({ error: 'invalid_grant' });
      // rotate access token, keep the SF creds
      const newToken = 'mt_' + rand(28);
      sessions.set(newToken, sess);
      sessions.delete(ourToken);
      refreshMap.set(refresh_token, newToken);
      return res.json({ access_token: newToken, token_type: 'Bearer', expires_in: 3600, refresh_token, scope: 'mcp' });
    }
    return res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (e) {
    log('/token error', e.message);
    return res.status(500).json({ error: 'server_error' });
  }
});

// =====================  Salesforce token helper  ============================
async function sfToken(params) {
  const body = new URLSearchParams({ client_id: SF_CLIENT_ID, client_secret: SF_CLIENT_SECRET, ...params });
  const r = await fetch(SF_TOKEN_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const text = await r.text();
  if (!r.ok) throw new Error(`token endpoint ${r.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

// =====================  MCP endpoint (Streamable HTTP)  =====================
function challenge(req, res) {
  const b = baseUrl(req);
  res.set('WWW-Authenticate', `Bearer resource_metadata="${b}/.well-known/oauth-protected-resource"`);
  return res.status(401).json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'authorization required' } });
}

async function parseBody(resp) {
  const text = await resp.text();
  if (!text || !text.trim()) return null;
  const ct = (resp.headers.get('content-type') || '').toLowerCase();
  if (ct.includes('text/event-stream') || /^\s*(event|data):/m.test(text)) {
    const datas = text.split('\n').filter(l => l.startsWith('data:')).map(l => l.slice(5).trim()).filter(Boolean);
    for (let i = datas.length - 1; i >= 0; i--) { try { return JSON.parse(datas[i]); } catch (_) {} }
    return null;
  }
  try { return JSON.parse(text); } catch (_) { return null; }
}

// Forward one JSON-RPC message to Salesforce with the session's SF token.
async function forward(sess, message, expectResponse) {
  const attempts = expectResponse ? 6 : 2;
  let didRefresh = false;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const headers = {
      'Authorization': 'Bearer ' + sess.sfAccessToken,
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'MCP-Protocol-Version': sess.protocol || '2025-06-18',
    };
    if (sess.sfSessionId) headers['mcp-session-id'] = sess.sfSessionId;
    let resp;
    try { resp = await fetch(SF_MCP_URL, { method: 'POST', headers, body: JSON.stringify(message) }); }
    catch (e) { log('sf network error', e.message); await new Promise(r => setTimeout(r, 300 * attempt)); continue; }

    if (resp.status === 401) {
      if (!didRefresh && sess.sfRefreshToken) {
        try {
          const j = await sfToken({ grant_type: 'refresh_token', refresh_token: sess.sfRefreshToken, resource: SF_MCP_URL });
          sess.sfAccessToken = j.access_token;
          if (j.refresh_token) sess.sfRefreshToken = j.refresh_token;
          didRefresh = true; attempt--; continue;
        } catch (e) { log('sf refresh failed', e.message); }
      }
      const detail = await resp.text().catch(() => '');
      return { jsonrpc: '2.0', id: message.id, error: { code: -32001, message: 'salesforce auth failed (401)' + (detail ? ': ' + detail.slice(0, 200) : '') } };
    }
    const sid = resp.headers.get('mcp-session-id');
    if (sid) sess.sfSessionId = sid;
    if (!expectResponse) return null;
    const parsed = await parseBody(resp);
    if (parsed) return parsed;
    log(`empty body for ${message.method} (attempt ${attempt})`);
    await new Promise(r => setTimeout(r, 250 * attempt));
  }
  return { jsonrpc: '2.0', id: message.id, error: { code: -32002, message: 'salesforce returned empty body after retries' } };
}

function toJsonRpc(resp, id) {
  if (resp && resp.jsonrpc === '2.0' && (resp.result !== undefined || resp.error !== undefined)) return resp;
  const detail = resp == null ? 'empty response' : JSON.stringify(resp);
  return { jsonrpc: '2.0', id, error: { code: -32003, message: 'malformed response from salesforce: ' + detail } };
}

app.post('/mcp', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const sess = token && sessions.get(token);
  if (!sess) return challenge(req, res);

  const msg = req.body;
  const isNotification = msg && msg.method && !Object.prototype.hasOwnProperty.call(msg, 'id');

  if (msg && msg.method === 'initialize') {
    sess.protocol = (msg.params && msg.params.protocolVersion) || sess.protocol;
    const out = toJsonRpc(await forward(sess, msg, true), msg.id);
    if (out.result && out.result.protocolVersion) sess.protocol = out.result.protocolVersion;
    return res.json(out);
  }
  if (isNotification) { await forward(sess, msg, false); return res.status(202).end(); }
  return res.json(toJsonRpc(await forward(sess, msg, true), msg.id));
});
// Some clients probe GET /mcp (SSE). We only support POST; return 405 cleanly.
app.get('/mcp', (req, res) => res.set('Allow', 'POST').status(405).json({ error: 'use POST' }));

app.get('/', (req, res) => res.type('text').send('Makana public MCP server. MCP endpoint: POST /mcp'));
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.error(`[makana-mcp] listening on :${PORT}`));
