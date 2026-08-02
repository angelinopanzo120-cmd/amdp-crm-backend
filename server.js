/* ============================================================================
   AMDP — Servidor de sincronização em tempo real (multi-utilizador)
   ----------------------------------------------------------------------------
   Versão SEM dependências externas: usa o SQLite embutido do Node (node:sqlite).
   Requer Node.js 22.5+ (o Dockerfile usa node:22-slim).

   Endpoints (iguais aos que o sistema.html chama):
     POST /api/auth/register  · POST /api/auth/login · POST /api/auth/password
     GET/PUT /api/dados (snapshot) · POST /api/sync/push · GET /api/sync/pull
     GET /api/sync/stream (SSE tempo real)
     GET /api/users · POST /api/users/create|update|delete
     POST /api/fiscal/next (numeração sequencial atómica) · GET /api/auditoria
   ========================================================================== */

'use strict';
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { DatabaseSync } = require('node:sqlite');

// ── Configuração (variáveis de ambiente) ───────────────────────────────────
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data'); // monte um volume persistente aqui
const AUTH_SECRET = process.env.AUTH_SECRET || 'troque-este-segredo-em-producao';
const TOKEN_TTL_DAYS = Number(process.env.TOKEN_TTL_DAYS || 30);
// Recuperação de palavra-passe por email (Resend — API HTTP, sem dependências)
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'AMDP <onboarding@resend.dev>';
const RESET_TTL_MIN = Number(process.env.RESET_TTL_MIN || 15);
const APP_NAME = process.env.APP_NAME || 'AMDP';
// Armazenamento de ficheiros — Cloudflare R2 (S3), sem dependências
const R2_ENDPOINT = (process.env.R2_ENDPOINT || '').replace(/\/$/, '');   // https://<acct>.r2.cloudflarestorage.com
const R2_BUCKET = process.env.R2_BUCKET || '';
const R2_ACCESS_KEY = process.env.R2_ACCESS_KEY || '';
const R2_SECRET = process.env.R2_SECRET || '';
const R2_PUBLIC_URL = (process.env.R2_PUBLIC_URL || '').replace(/\/$/, ''); // https://pub-xxxx.r2.dev
const R2_OK = !!(R2_ENDPOINT && R2_BUCKET && R2_ACCESS_KEY && R2_SECRET && R2_PUBLIC_URL);

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'amdp.db'));
db.exec('PRAGMA journal_mode = WAL;');    // leituras concorrentes + durabilidade
db.exec('PRAGMA synchronous = NORMAL;');
db.exec('PRAGMA foreign_keys = ON;');

// ── Esquema ─────────────────────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS tenants (
  id        TEXT PRIMARY KEY,
  nome      TEXT,
  ver       INTEGER NOT NULL DEFAULT 0,
  criado_em TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  pass_hash  TEXT NOT NULL,
  nome       TEXT,
  role       TEXT DEFAULT 'Comercial',
  ativo      INTEGER NOT NULL DEFAULT 1,
  criado_em  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(lower(email));
CREATE TABLE IF NOT EXISTS records (
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  tabela      TEXT NOT NULL,
  registo_id  TEXT NOT NULL,
  dados       TEXT,
  deleted     INTEGER NOT NULL DEFAULT 0,
  ver         INTEGER NOT NULL,
  client_id   TEXT,
  autor       TEXT,
  updated_at  TEXT,
  PRIMARY KEY (tenant_id, tabela, registo_id)
);
CREATE INDEX IF NOT EXISTS ix_records_ver ON records(tenant_id, ver);
CREATE TABLE IF NOT EXISTS auditoria (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id  TEXT NOT NULL,
  autor      TEXT,
  op         TEXT,
  tabela     TEXT,
  registo_id TEXT,
  ts         TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_tenant ON auditoria(tenant_id, id DESC);
CREATE TABLE IF NOT EXISTS fiscal_seq (
  tenant_id TEXT NOT NULL,
  chave     TEXT NOT NULL,
  seq       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, chave)
);
CREATE TABLE IF NOT EXISTS pw_resets (
  email     TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires   INTEGER NOT NULL,
  attempts  INTEGER NOT NULL DEFAULT 0,
  criado_em TEXT
);
`);

// migração idempotente: áreas de negócio por utilizador
try { db.exec("ALTER TABLE users ADD COLUMN areas TEXT DEFAULT '[]'"); } catch (e) {}

// ── Utilitários: palavra-passe (scrypt) e token (HMAC) ──────────────────────
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + dk.toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const parts = String(stored).split('$');
    const salt = Buffer.from(parts[1], 'hex');
    const hash = Buffer.from(parts[2], 'hex');
    const dk = crypto.scryptSync(String(pw), salt, 64);
    return dk.length === hash.length && crypto.timingSafeEqual(dk, hash);
  } catch (e) { return false; }
}
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function signToken(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', AUTH_SECRET).update(body).digest());
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const body = token.slice(0, i), sig = token.slice(i + 1);
  const exp = b64url(crypto.createHmac('sha256', AUTH_SECRET).update(body).digest());
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null;
  let p; try { p = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch (e) { return null; }
  if (p.exp && Date.now() > p.exp) return null;
  return p;
}
function newId(pfx) { return (pfx || '') + crypto.randomBytes(9).toString('hex'); }
function now() { return new Date().toISOString(); }
function isAdmin(role) { return /^admin/i.test(String(role || '')); }
function _areasArr(v){ try{ var a=JSON.parse(v||'[]'); return Array.isArray(a)?a:[]; }catch(e){ return []; } }
function _areasStr(v){ try{ if(Array.isArray(v)) return JSON.stringify(v.filter(Boolean)); if(typeof v==='string'){ var t=v.trim(); return t.charAt(0)==='['?t:JSON.stringify(t.split(',').map(function(x){return x.trim();}).filter(Boolean)); } return '[]'; }catch(e){ return '[]'; } }

// ── Recuperação de palavra-passe: código + envio de email ───────────────────
function hashCode(email, code) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(String(email).toLowerCase() + ':' + String(code)).digest('hex');
}
const _forgotRate = new Map(); // email -> timestamp do último pedido
function sendEmail(to, subject, html) {
  return new Promise((resolve) => {
    if (!RESEND_API_KEY) { console.warn('[email] RESEND_API_KEY em falta — email NAO enviado para ' + to); return resolve(false); }
    const payload = JSON.stringify({ from: MAIL_FROM, to: [to], subject: subject, html: html });
    const rq = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Length': Buffer.byteLength(payload) }
    }, (resp) => { let d = ''; resp.on('data', c => d += c); resp.on('end', () => { const ok = resp.statusCode >= 200 && resp.statusCode < 300; if (!ok) console.error('[email] falhou ' + resp.statusCode + ' ' + d.slice(0, 200)); resolve(ok); }); });
    rq.on('error', (e) => { console.error('[email] erro: ' + e.message); resolve(false); });
    rq.write(payload); rq.end();
  });
}

// ── Acesso a dados (statements preparados) ──────────────────────────────────
const Q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  usersByTenant: db.prepare('SELECT id,email,nome,role,areas,ativo FROM users WHERE tenant_id=? ORDER BY criado_em'),
  insTenant: db.prepare('INSERT INTO tenants(id,nome,ver,criado_em) VALUES(?,?,0,?)'),
  insUser: db.prepare('INSERT INTO users(id,tenant_id,email,pass_hash,nome,role,areas,ativo,criado_em) VALUES(?,?,?,?,?,?,?,1,?)'),
  updUserPass: db.prepare('UPDATE users SET pass_hash=? WHERE id=?'),
  updUser: db.prepare('UPDATE users SET nome=?, role=?, areas=? WHERE id=? AND tenant_id=?'),
  delUser: db.prepare('DELETE FROM users WHERE id=? AND tenant_id=?'),
  tenantVer: db.prepare('SELECT ver FROM tenants WHERE id=?'),
  bumpTenant: db.prepare('UPDATE tenants SET ver=? WHERE id=?'),
  upsertRec: db.prepare(`INSERT INTO records(tenant_id,tabela,registo_id,dados,deleted,ver,client_id,autor,updated_at)
                         VALUES(?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(tenant_id,tabela,registo_id) DO UPDATE SET
                           dados=excluded.dados, deleted=excluded.deleted, ver=excluded.ver,
                           client_id=excluded.client_id, autor=excluded.autor, updated_at=excluded.updated_at`),
  changesSince: db.prepare('SELECT tabela,registo_id,dados,deleted FROM records WHERE tenant_id=? AND ver>? ORDER BY ver'),
  allRecs: db.prepare('SELECT tabela,registo_id,dados FROM records WHERE tenant_id=? AND deleted=0'),
  insAudit: db.prepare('INSERT INTO auditoria(tenant_id,autor,op,tabela,registo_id,ts) VALUES(?,?,?,?,?,?)'),
  auditByTenant: db.prepare('SELECT autor,op,tabela,registo_id AS registoId,ts FROM auditoria WHERE tenant_id=? ORDER BY id DESC LIMIT 500'),
  fiscalGet: db.prepare('SELECT seq FROM fiscal_seq WHERE tenant_id=? AND chave=?'),
  fiscalSet: db.prepare('INSERT INTO fiscal_seq(tenant_id,chave,seq) VALUES(?,?,?) ON CONFLICT(tenant_id,chave) DO UPDATE SET seq=excluded.seq'),
  resetGet: db.prepare('SELECT * FROM pw_resets WHERE email=?'),
  resetSet: db.prepare('INSERT INTO pw_resets(email,code_hash,expires,attempts,criado_em) VALUES(?,?,?,0,?) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash, expires=excluded.expires, attempts=0, criado_em=excluded.criado_em'),
  resetDel: db.prepare('DELETE FROM pw_resets WHERE email=?'),
  resetBump: db.prepare('UPDATE pw_resets SET attempts=attempts+1 WHERE email=?'),
};

// Transação simples (node:sqlite não tem helper próprio).
function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) { } throw e; }
}

// Aplica um lote de alterações de forma ATÓMICA e devolve a nova versão.
function applyChanges(tenantId, clientId, autor, changes) {
  return tx(() => {
    const row = Q.tenantVer.get(tenantId);
    let ver = Number((row && row.ver) || 0);
    for (const ch of changes) {
      if (!ch || !ch.tabela || ch.registoId == null) continue;
      ver += 1;
      const del = ch.op === 'delete' ? 1 : 0;
      Q.upsertRec.run(tenantId, String(ch.tabela), String(ch.registoId),
        del ? null : JSON.stringify(ch.dados), del, ver, clientId || null, autor || null, now());
      Q.insAudit.run(tenantId, autor || '', del ? 'eliminar' : 'alterar', String(ch.tabela), String(ch.registoId), now());
    }
    Q.bumpTenant.run(ver, tenantId);
    return ver;
  });
}

// Numeração fiscal sequencial e ATÓMICA (à prova de emissão simultânea em vários postos).
// n = max(contador atual, mínimo enviado pelo cliente) + 1  → nunca repete nem recua.
function nextFiscalSeq(tenantId, chave, min) {
  return tx(() => {
    const row = Q.fiscalGet.get(tenantId, chave);
    const base = Math.max(Number((row && row.seq) || 0), Number(min) || 0);
    const n = base + 1;
    Q.fiscalSet.run(tenantId, chave, n);
    return n;
  });
}

// ── SSE: clientes ligados por tenant (distribuição em tempo real) ───────────
const streams = new Map(); // tenantId -> Set<{res, clientId}>
function broadcast(tenantId, originClientId, changes, ver) {
  const set = streams.get(tenantId); if (!set || !set.size) return;
  const payload = 'data: ' + JSON.stringify({ changes, ver }) + '\n\n';
  for (const c of set) {
    if (originClientId && c.clientId === originClientId) continue; // não devolver ao próprio emissor
    try { c.res.write(payload); } catch (e) { }
  }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────
function send(res, code, obj) {
  const body = JSON.stringify(obj == null ? {} : obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 25 * 1024 * 1024) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
function urlOf(req) { return new URL(req.url, 'http://localhost'); }
function auth(req) {
  const h = req.headers['authorization'] || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : (urlOf(req).searchParams.get('token') || '');
  const p = verifyToken(tok);
  if (!p) return null;
  const u = Q.userById.get(p.uid);
  if (!u || Number(u.ativo) === 0) return null;
  return u; // {id,tenant_id,email,nome,role,...}
}
function tokenForUser(u) {
  return signToken({ uid: u.id, tid: u.tenant_id, role: u.role, exp: Date.now() + TOKEN_TTL_DAYS * 864e5 });
}

// ── Cloudflare R2 (upload S3 com assinatura SigV4, sem dependências) ─────────
function _hmac(key, data) { return crypto.createHmac('sha256', key).update(data, 'utf8').digest(); }
function _sha256hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function r2Put(key, buf, contentType) {
  return new Promise((resolve, reject) => {
    try {
      const host = R2_ENDPOINT.replace(/^https?:\/\//, '');
      const canonicalUri = '/' + R2_BUCKET + '/' + key.split('/').map(encodeURIComponent).join('/');
      const amzdate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
      const datestamp = amzdate.slice(0, 8);
      const region = 'auto', service = 's3';
      const payloadHash = _sha256hex(buf);
      const ct = contentType || 'application/octet-stream';
      const canonicalHeaders = 'content-type:' + ct + '\nhost:' + host + '\nx-amz-content-sha256:' + payloadHash + '\nx-amz-date:' + amzdate + '\n';
      const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
      const canonicalRequest = ['PUT', canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
      const scope = datestamp + '/' + region + '/' + service + '/aws4_request';
      const stringToSign = ['AWS4-HMAC-SHA256', amzdate, scope, _sha256hex(Buffer.from(canonicalRequest, 'utf8'))].join('\n');
      const kSigning = _hmac(_hmac(_hmac(_hmac('AWS4' + R2_SECRET, datestamp), region), service), 'aws4_request');
      const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');
      const authorization = 'AWS4-HMAC-SHA256 Credential=' + R2_ACCESS_KEY + '/' + scope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
      const rq = https.request({
        method: 'PUT', host: host, path: canonicalUri,
        headers: { 'Host': host, 'Content-Type': ct, 'Content-Length': buf.length, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzdate, 'Authorization': authorization }
      }, (rs) => {
        let body = ''; rs.on('data', c => body += c);
        rs.on('end', () => { (rs.statusCode >= 200 && rs.statusCode < 300) ? resolve(true) : reject(new Error('R2 ' + rs.statusCode + ' ' + body.slice(0, 300))); });
      });
      rq.on('error', reject); rq.write(buf); rq.end();
    } catch (e) { reject(e); }
  });
}

// ── Servidor ────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const u = urlOf(req);
  const p = u.pathname;
  try {
    // — Saúde —
    if (p === '/' || p === '/api/health') return send(res, 200, { ok: true, servico: 'AMDP sync', versao: 'areas-v2', areasNoServidor: true, r2: R2_OK, tempo: now() });

    // — Upload de ficheiros para o R2 —
    if (p === '/api/files' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!R2_OK) return send(res, 500, { error: 'Armazenamento de ficheiros não configurado no servidor' });
      const b = await readBody(req);
      let data = String(b.dataBase64 || b.data || '');
      let ctype = String(b.type || '');
      const mm = data.match(/^data:([^;]+);base64,(.*)$/);
      if (mm) { ctype = ctype || mm[1]; data = mm[2]; }
      if (!data) return send(res, 400, { error: 'Sem ficheiro' });
      let buf; try { buf = Buffer.from(data, 'base64'); } catch (e) { return send(res, 400, { error: 'Ficheiro inválido' }); }
      if (!buf.length) return send(res, 400, { error: 'Ficheiro vazio' });
      const nome = String(b.name || 'ficheiro');
      const ext = (nome.split('.').pop() || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toLowerCase() || 'bin';
      const key = me.tenant_id + '/' + newId('f_') + '_' + Date.now() + '.' + ext;
      try { await r2Put(key, buf, ctype || 'application/octet-stream'); }
      catch (e) { return send(res, 502, { error: 'Falha ao guardar no R2: ' + (e && e.message || e) }); }
      return send(res, 200, { ok: true, url: R2_PUBLIC_URL + '/' + key, key: key, size: buf.length });
    }

    // — Registo (cria empresa + administrador) —
    if (p === '/api/auth/register' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!email || !pass) return send(res, 400, { error: 'Indique email e palavra-passe' });
      if (Q.userByEmail.get(email)) return send(res, 409, { error: 'Já existe uma conta com esse email. Use Entrar.' });
      const tid = newId('t_');
      Q.insTenant.run(tid, email.split('@')[0] + ' (empresa)', now());
      const uid = newId('u_');
      const nome = email.split('@')[0];
      Q.insUser.run(uid, tid, email, hashPassword(pass), nome, 'Administrador', '[]', now());
      const user = Q.userById.get(uid);
      return send(res, 200, { token: tokenForUser(user), nome: user.nome, role: user.role, email: user.email, areas: _areasArr(user.areas) });
    }

    // — Entrar —
    if (p === '/api/auth/login' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      const user = Q.userByEmail.get(email);
      if (!user || Number(user.ativo) === 0 || !verifyPassword(pass, user.pass_hash)) return send(res, 401, { error: 'Email ou palavra-passe incorrectos' });
      return send(res, 200, { token: tokenForUser(user), nome: user.nome, role: user.role, email: user.email, areas: _areasArr(user.areas) });
    }

    // — Trocar a própria palavra-passe —
    if (p === '/api/auth/password' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      if (!verifyPassword(String(b.currentPassword || ''), me.pass_hash)) return send(res, 400, { error: 'Palavra-passe actual incorrecta' });
      if (String(b.newPassword || '').length < 3) return send(res, 400, { error: 'Nova palavra-passe demasiado curta' });
      Q.updUserPass.run(hashPassword(String(b.newPassword)), me.id);
      return send(res, 200, { ok: true });
    }

    // — Snapshot completo (reserva/compatibilidade) —
    if (p === '/api/dados' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const rows = Q.allRecs.all(me.tenant_id);
      const dados = {};
      for (const r of rows) {
        const key = 'amdp_crm_' + r.tabela;
        if (!dados[key]) dados[key] = [];
        try { dados[key].push(JSON.parse(r.dados)); } catch (e) { }
      }
      Object.keys(dados).forEach(k => { dados[k] = JSON.stringify(dados[k]); });
      return send(res, 200, { dados });
    }
    if (p === '/api/dados' && req.method === 'PUT') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      const dados = (b && b.dados) || {};
      const changes = [];
      Object.keys(dados).forEach(k => {
        if (k.indexOf('amdp_crm_') !== 0) return;
        const tabela = k.slice('amdp_crm_'.length);
        if (tabela === 'auditoria') return;
        let arr; try { arr = JSON.parse(typeof dados[k] === 'string' ? dados[k] : JSON.stringify(dados[k])); } catch (e) { return; }
        if (Array.isArray(arr)) arr.forEach(rec => { if (rec && rec.id != null) changes.push({ tabela, registoId: rec.id, op: 'upsert', dados: rec }); });
      });
      const ver = applyChanges(me.tenant_id, null, me.nome, changes);
      broadcast(me.tenant_id, null, changes.map(c => ({ tabela: c.tabela, registoId: c.registoId, op: 'upsert', dados: c.dados })), ver);
      return send(res, 200, { ok: true, ver });
    }

    // — Sincronização incremental: ENVIAR —
    if (p === '/api/sync/push' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      const changes = Array.isArray(b.changes) ? b.changes : [];
      const clientId = b.clientId || null;
      const ver = applyChanges(me.tenant_id, clientId, me.nome, changes);
      broadcast(me.tenant_id, clientId, changes.map(c => ({
        tabela: c.tabela, registoId: c.registoId, op: c.op === 'delete' ? 'delete' : 'upsert', dados: c.op === 'delete' ? null : c.dados,
      })), ver);
      return send(res, 200, { ver });
    }

    // — Sincronização incremental: DESCARREGAR (catch-up) —
    if (p === '/api/sync/pull' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const since = Number(u.searchParams.get('since') || 0);
      const rows = Q.changesSince.all(me.tenant_id, since);
      const changes = rows.map(r => ({
        tabela: r.tabela, registoId: r.registo_id, op: r.deleted ? 'delete' : 'upsert',
        dados: r.deleted ? null : (() => { try { return JSON.parse(r.dados); } catch (e) { return null; } })(),
      }));
      const vrow = Q.tenantVer.get(me.tenant_id);
      const ver = Number((vrow && vrow.ver) || 0);
      return send(res, 200, { changes, ver });
    }

    // — Tempo real: canal SSE —
    if (p === '/api/sync/stream' && req.method === 'GET') {
      const me = auth(req); if (!me) { res.writeHead(401); return res.end(); }
      const clientId = u.searchParams.get('clientId') || newId('c_');
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      res.write('retry: 3000\n\n');
      res.write(': ligado\n\n');
      if (!streams.has(me.tenant_id)) streams.set(me.tenant_id, new Set());
      const entry = { res, clientId };
      streams.get(me.tenant_id).add(entry);
      const ka = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { } }, 25000);
      req.on('close', () => { clearInterval(ka); const s = streams.get(me.tenant_id); if (s) s.delete(entry); });
      return; // mantém a ligação aberta
    }

    // — Utilizadores (só Administrador) —
    if (p === '/api/users' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      return send(res, 200, { users: Q.usersByTenant.all(me.tenant_id).map(x => ({ id: x.id, email: x.email, nome: x.nome, role: x.role, ativo: Number(x.ativo) !== 0, areas: _areasArr(x.areas) })) });
    }
    if (p === '/api/users/create' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!email || !pass) return send(res, 400, { error: 'Email e palavra-passe obrigatórios' });
      if (Q.userByEmail.get(email)) return send(res, 409, { error: 'Email já existe' });
      Q.insUser.run(newId('u_'), me.tenant_id, email, hashPassword(pass), String(b.nome || email.split('@')[0]), String(b.role || 'Comercial'), _areasStr(b.areas), now());
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users/update' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const target = Q.userById.get(String(b.id || ''));
      if (!target || target.tenant_id !== me.tenant_id) return send(res, 404, { error: 'Conta não encontrada' });
      Q.updUser.run(String(b.nome || target.nome), String(b.role || target.role), (b.areas !== undefined ? _areasStr(b.areas) : (target.areas || '[]')), target.id, me.tenant_id);
      if (b.password) Q.updUserPass.run(hashPassword(String(b.password)), target.id);
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users/delete' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const target = Q.userById.get(String(b.id || ''));
      if (!target || target.tenant_id !== me.tenant_id) return send(res, 404, { error: 'Conta não encontrada' });
      if (target.id === me.id) return send(res, 400, { error: 'Não pode eliminar a sua própria conta' });
      Q.delUser.run(target.id, me.tenant_id);
      return send(res, 200, { ok: true });
    }

    // — Numeração fiscal sequencial (atómica, partilhada entre postos) —
    if (p === '/api/fiscal/next' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      const chave = String(b.key || '').slice(0, 80); if (!chave) return send(res, 400, { error: 'Chave em falta' });
      const seq = nextFiscalSeq(me.tenant_id, chave, b.min);
      return send(res, 200, { seq });
    }

    // — Auditoria (registo da empresa) —
    if (p === '/api/auditoria' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      return send(res, 200, { movimentos: Q.auditByTenant.all(me.tenant_id) });
    }

    // — Recuperação: pedir código por email —
    if (p === '/api/auth/forgot' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const generic = () => send(res, 200, { ok: true }); // resposta genérica (não revela se a conta existe)
      if (!email) return generic();
      const last = _forgotRate.get(email) || 0;
      if (Date.now() - last < 60000) return generic();     // 1 pedido / 60s por email
      _forgotRate.set(email, Date.now());
      const user = Q.userByEmail.get(email);
      if (user && Number(user.ativo) !== 0) {
        const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digitos
        Q.resetSet.run(email, hashCode(email, code), Date.now() + RESET_TTL_MIN * 60000, now());
        const html = '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:auto;color:#0a2540">'
          + '<h2 style="margin:0 0 8px">' + APP_NAME + ' - Recuperacao de palavra-passe</h2>'
          + '<p>Recebemos um pedido para repor a palavra-passe da sua conta.</p>'
          + '<p>O seu codigo de recuperacao e:</p>'
          + '<p style="font-size:30px;font-weight:bold;letter-spacing:6px">' + code + '</p>'
          + '<p>Este codigo expira em ' + RESET_TTL_MIN + ' minutos. Se nao foi voce a pedir, ignore este email.</p>'
          + '</div>';
        sendEmail(email, APP_NAME + ' - Codigo de recuperacao', html); // não aguardamos (resposta imediata e genérica)
      }
      return generic();
    }

    // — Recuperação: definir nova palavra-passe com o código —
    if (p === '/api/auth/reset' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const code = String(b.code || '').trim();
      const np = String(b.newPassword || '');
      if (!email || !code || !np) return send(res, 400, { error: 'Dados incompletos' });
      if (np.length < 3) return send(res, 400, { error: 'Nova palavra-passe demasiado curta' });
      const row = Q.resetGet.get(email);
      if (!row) return send(res, 400, { error: 'Codigo invalido ou expirado' });
      if (Date.now() > Number(row.expires)) { Q.resetDel.run(email); return send(res, 400, { error: 'Codigo expirado. Peca um novo.' }); }
      if (Number(row.attempts) >= 5) { Q.resetDel.run(email); return send(res, 400, { error: 'Demasiadas tentativas. Peca um novo codigo.' }); }
      const a = Buffer.from(String(row.code_hash)); const bb = Buffer.from(hashCode(email, code));
      const good = a.length === bb.length && crypto.timingSafeEqual(a, bb);
      if (!good) { Q.resetBump.run(email); return send(res, 400, { error: 'Codigo invalido' }); }
      const user = Q.userByEmail.get(email);
      if (!user) { Q.resetDel.run(email); return send(res, 400, { error: 'Conta nao encontrada' }); }
      Q.updUserPass.run(hashPassword(np), user.id);
      Q.resetDel.run(email);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'Endpoint não encontrado' });
  } catch (e) {
    return send(res, 500, { error: 'Erro interno: ' + (e && e.message ? e.message : String(e)) });
  }
});

server.listen(PORT, () => {
  console.log('AMDP sync server (node:sqlite) a ouvir na porta ' + PORT + ' · dados em ' + DATA_DIR);
});
