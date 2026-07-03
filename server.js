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
const { DatabaseSync } = require('node:sqlite');

// ── Configuração (variáveis de ambiente) ───────────────────────────────────
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data'); // monte um volume persistente aqui
const AUTH_SECRET = process.env.AUTH_SECRET || 'troque-este-segredo-em-producao';
const TOKEN_TTL_DAYS = Number(process.env.TOKEN_TTL_DAYS || 30);

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
`);

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

// ── Acesso a dados (statements preparados) ──────────────────────────────────
const Q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  usersByTenant: db.prepare('SELECT id,email,nome,role,ativo FROM users WHERE tenant_id=? ORDER BY criado_em'),
  insTenant: db.prepare('INSERT INTO tenants(id,nome,ver,criado_em) VALUES(?,?,0,?)'),
  insUser: db.prepare('INSERT INTO users(id,tenant_id,email,pass_hash,nome,role,ativo,criado_em) VALUES(?,?,?,?,?,?,1,?)'),
  updUserPass: db.prepare('UPDATE users SET pass_hash=? WHERE id=?'),
  updUser: db.prepare('UPDATE users SET nome=?, role=? WHERE id=? AND tenant_id=?'),
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

// ── Servidor ────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const u = urlOf(req);
  const p = u.pathname;
  try {
    // — Saúde —
    if (p === '/' || p === '/api/health') return send(res, 200, { ok: true, servico: 'AMDP sync', tempo: now() });

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
      Q.insUser.run(uid, tid, email, hashPassword(pass), nome, 'Administrador', now());
      const user = Q.userById.get(uid);
      return send(res, 200, { token: tokenForUser(user), nome: user.nome, role: user.role, email: user.email });
    }

    // — Entrar —
    if (p === '/api/auth/login' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      const user = Q.userByEmail.get(email);
      if (!user || Number(user.ativo) === 0 || !verifyPassword(pass, user.pass_hash)) return send(res, 401, { error: 'Email ou palavra-passe incorrectos' });
      return send(res, 200, { token: tokenForUser(user), nome: user.nome, role: user.role, email: user.email });
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
      return send(res, 200, { users: Q.usersByTenant.all(me.tenant_id).map(x => ({ id: x.id, email: x.email, nome: x.nome, role: x.role, ativo: Number(x.ativo) !== 0 })) });
    }
    if (p === '/api/users/create' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!email || !pass) return send(res, 400, { error: 'Email e palavra-passe obrigatórios' });
      if (Q.userByEmail.get(email)) return send(res, 409, { error: 'Email já existe' });
      Q.insUser.run(newId('u_'), me.tenant_id, email, hashPassword(pass), String(b.nome || email.split('@')[0]), String(b.role || 'Comercial'), now());
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users/update' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const target = Q.userById.get(String(b.id || ''));
      if (!target || target.tenant_id !== me.tenant_id) return send(res, 404, { error: 'Conta não encontrada' });
      Q.updUser.run(String(b.nome || target.nome), String(b.role || target.role), target.id, me.tenant_id);
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

    return send(res, 404, { error: 'Endpoint não encontrado' });
  } catch (e) {
    return send(res, 500, { error: 'Erro interno: ' + (e && e.message ? e.message : String(e)) });
  }
});

server.listen(PORT, () => {
  console.log('AMDP sync server (node:sqlite) a ouvir na porta ' + PORT + ' · dados em ' + DATA_DIR);
});
