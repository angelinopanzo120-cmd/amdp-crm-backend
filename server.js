'use strict';
/*
 * AMDP CRM — Backend próprio (Node.js, sem dependências externas)
 * - Autenticação por email + palavra-passe (scrypt) com token JWT (HS256)
 * - Sincronização do conjunto de dados por conta (pull/push)
 * - Serve o site (public/index.html)
 * - Proxy opcional para consulta de NIF na AGT (AGT_NIF_URL com {nif})
 *
 * Variáveis de ambiente (todas opcionais, com valores por defeito):
 *   PORT=8080
 *   JWT_SECRET=<gere um segredo forte>   (OBRIGATÓRIO em produção)
 *   DATA_DIR=./data                      (onde ficam os dados em disco)
 *   PUBLIC_DIR=./public                  (onde está o index.html)
 *   CORS_ORIGIN=*                        (origem permitida; use o seu domínio em produção)
 *   AGT_NIF_URL=                         (ex.: https://.../contribuinte?nif={nif})
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8080', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, 'public');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const AGT_NIF_URL = process.env.AGT_NIF_URL || '';

if (JWT_SECRET === 'troque-este-segredo-em-producao') {
  console.warn('[AVISO] Defina a variável JWT_SECRET com um segredo forte antes de usar em produção.');
}

/* ---------- Persistência simples em ficheiro (sem dependências) ---------- */
const DB_FILE = path.join(DATA_DIR, 'db.json');
const WS = 'empresa';  // espaço de dados partilhado por todos os funcionários
function _ensure() { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], datasets: {}, records: {}, seq: {} })); }
function loadDB() { _ensure(); try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { return { users: [], datasets: {}, records: {}, seq: {} }; } }
let _writeQueue = Promise.resolve();
function saveDB(db) { const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); }

/* Consolida dados antigos (guardados por conta) num único espaço partilhado da empresa.
   Corre uma só vez; preserva os dados já existentes escolhendo o conjunto com mais registos. */
function migrarParaPartilhado(db) {
  db.records = db.records || {}; db.seq = db.seq || {}; db.datasets = db.datasets || {};
  if (db._wsMigrado) return db;
  if (!db.records[WS]) {
    let best = null, bestN = -1;
    Object.keys(db.records).forEach(uid => { if (uid === WS) return; const n = Object.keys(db.records[uid] || {}).length; if (n > bestN) { bestN = n; best = uid; } });
    db.records[WS] = best ? db.records[best] : {};
    db.seq[WS] = best ? (db.seq[best] || 0) : 0;
  }
  if (!db.datasets[WS]) {
    let best = null, bestN = -1;
    Object.keys(db.datasets).forEach(uid => { if (uid === WS) return; const dd = (db.datasets[uid] && db.datasets[uid].dados) || {}; const n = Object.keys(dd).length; if (n > bestN) { bestN = n; best = uid; } });
    db.datasets[WS] = best ? db.datasets[best] : { dados: {}, atualizado: null };
  }
  db._wsMigrado = true;
  return db;
}
function isAdmin(a) { return a && (a.role === 'Administrador' || a.role === 'admin'); }

/* ---------- Auth: scrypt + JWT (HS256) ---------- */
function hashPassword(pass) { const salt = crypto.randomBytes(16).toString('hex'); const dk = crypto.scryptSync(pass, salt, 32).toString('hex'); return salt + ':' + dk; }
function verifyPassword(pass, stored) { try { const [salt, dk] = stored.split(':'); const test = crypto.scryptSync(pass, salt, 32).toString('hex'); return crypto.timingSafeEqual(Buffer.from(dk), Buffer.from(test)); } catch (e) { return false; } }
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlJSON(o) { return b64url(JSON.stringify(o)); }
function signToken(payload) {
  const header = b64urlJSON({ alg: 'HS256', typ: 'JWT' });
  const body = b64urlJSON(Object.assign({ iat: Math.floor(Date.now() / 1000) }, payload));
  const data = header + '.' + body;
  const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(data).digest());
  return data + '.' + sig;
}
function verifyToken(token) {
  try {
    const [h, b, s] = String(token || '').split('.');
    if (!h || !b || !s) return null;
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(h + '.' + b).digest());
    if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return null;
    return JSON.parse(Buffer.from(b.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch (e) { return null; }
}

/* ---------- Tempo real (SSE) partilhado pela empresa ---------- */
let _sseList = []; // [ {clientId, res} ]
function sseAdd(clientId, res) { _sseList.push({ clientId: clientId, res: res }); }
function sseRemove(res) { _sseList = _sseList.filter(c => c.res !== res); }
function sseBroadcast(payload, exceptClientId) {
  const data = 'data: ' + JSON.stringify(payload) + '\n\n';
  _sseList.forEach(c => { if (c.clientId && c.clientId === exceptClientId) return; try { c.res.write(data); } catch (e) { } });
}

/* ---------- Utilitários HTTP ---------- */
function cors(res) { res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS'); }
function sendJSON(res, code, obj) { cors(res); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); }
function readBody(req) { return new Promise((resolve) => { let d = ''; req.on('data', c => { d += c; if (d.length > 25 * 1024 * 1024) req.destroy(); }); req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { resolve(null); } }); }); }
function authUser(req) { const h = req.headers['authorization'] || ''; const m = h.match(/^Bearer\s+(.+)$/i); if (!m) return null; return verifyToken(m[1]); }

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };
function serveStatic(req, res) {
  let p = decodeURIComponent((req.url.split('?')[0]) || '/');
  if (p === '/' || p === '') p = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, p));
  if (full.indexOf(path.normalize(PUBLIC_DIR)) !== 0) { res.writeHead(403); res.end('forbidden'); return; }
  fs.readFile(full, (err, buf) => {
    if (err) { // fallback para a SPA
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, idx) => { if (e2) { res.writeHead(404); res.end('Not found'); } else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(idx); } });
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
    res.end(buf);
  });
}

/* ---------- Servidor ---------- */
const server = http.createServer(async (req, res) => {
  const url = (req.url || '').split('?')[0];
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }

  // -- API --
  if (url.indexOf('/api/') === 0) {
    try {
      if (url === '/api/health') return sendJSON(res, 200, { ok: true, ts: new Date().toISOString() });

      if (url === '/api/auth/register' && req.method === 'POST') {
        const b = await readBody(req); if (!b) return sendJSON(res, 400, { error: 'JSON inválido' });
        const email = String(b.email || '').trim().toLowerCase(); const pass = String(b.password || '');
        if (!email || !pass) return sendJSON(res, 400, { error: 'Email e palavra-passe obrigatórios' });
        const db = loadDB();
        // Só permite registo livre para a PRIMEIRA conta (o Administrador). Depois, contas são criadas pelo Administrador.
        if (db.users.length > 0) return sendJSON(res, 403, { error: 'O registo está fechado. Peça ao Administrador para criar a sua conta.' });
        if (db.users.find(u => u.email === email)) return sendJSON(res, 409, { error: 'Já existe uma conta com esse email' });
        const id = crypto.randomUUID();
        const nome = String(b.nome || '').trim() || email;
        const role = 'Administrador';
        db.users.push({ id, email, pass: hashPassword(pass), nome, role, criado: new Date().toISOString() });
        migrarParaPartilhado(db); saveDB(db);
        return sendJSON(res, 200, { token: signToken({ uid: id, email, role }), email, nome, role });
      }

      if (url === '/api/auth/login' && req.method === 'POST') {
        const b = await readBody(req); if (!b) return sendJSON(res, 400, { error: 'JSON inválido' });
        const email = String(b.email || '').trim().toLowerCase(); const pass = String(b.password || '');
        const db = loadDB(); const u = db.users.find(x => x.email === email);
        if (!u || !verifyPassword(pass, u.pass)) return sendJSON(res, 401, { error: 'Credenciais inválidas' });
        const role = u.role || 'Administrador';
        return sendJSON(res, 200, { token: signToken({ uid: u.id, email, role }), email, nome: u.nome || email, role });
      }

      // ----- Alterar a própria palavra-passe (qualquer utilizador autenticado) -----
      if (url === '/api/auth/password' && req.method === 'POST') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const b = await readBody(req); if (!b) return sendJSON(res, 400, { error: 'JSON inválido' });
        const atual = String(b.currentPassword || ''); const nova = String(b.newPassword || '');
        if (nova.length < 3) return sendJSON(res, 400, { error: 'A nova palavra-passe é demasiado curta' });
        const db = loadDB(); const u = db.users.find(x => x.id === a.uid);
        if (!u) return sendJSON(res, 404, { error: 'Conta não encontrada' });
        if (!verifyPassword(atual, u.pass)) return sendJSON(res, 403, { error: 'Palavra-passe atual incorreta' });
        u.pass = hashPassword(nova); saveDB(db);
        return sendJSON(res, 200, { ok: true });
      }

      // ----- Registo de movimentos da empresa (só Administrador) -----
      if (url.indexOf('/api/auditoria') === 0 && req.method === 'GET') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        if (!isAdmin(a)) return sendJSON(res, 403, { error: 'Apenas o Administrador' });
        const db = loadDB(); const store = (db.records && db.records[WS]) || {};
        const lista = Object.keys(store).map(k => store[k])
          .map(e => ({ tabela: e.tabela, registoId: e.registoId, op: e.op, ts: e.ts, autor: e.autor || '', ver: e.ver }))
          .sort((x, y) => (y.ver || 0) - (x.ver || 0)).slice(0, 800);
        return sendJSON(res, 200, { movimentos: lista });
      }

      // ----- Gestão de contas de funcionários (só Administrador) -----
      if (url === '/api/users' && req.method === 'GET') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        if (!isAdmin(a)) return sendJSON(res, 403, { error: 'Apenas o Administrador' });
        const db = loadDB();
        return sendJSON(res, 200, { users: db.users.map(u => ({ id: u.id, email: u.email, nome: u.nome, role: u.role, criado: u.criado })) });
      }
      if (url === '/api/users/create' && req.method === 'POST') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        if (!isAdmin(a)) return sendJSON(res, 403, { error: 'Apenas o Administrador pode criar contas' });
        const b = await readBody(req); if (!b) return sendJSON(res, 400, { error: 'JSON inválido' });
        const email = String(b.email || '').trim().toLowerCase(); const pass = String(b.password || '');
        const nome = String(b.nome || '').trim() || email; const role = String(b.role || '').trim() || 'Consulta';
        if (!email || !pass) return sendJSON(res, 400, { error: 'Email e palavra-passe obrigatórios' });
        const db = loadDB();
        if (db.users.find(u => u.email === email)) return sendJSON(res, 409, { error: 'Já existe uma conta com esse email' });
        const id = crypto.randomUUID();
        db.users.push({ id, email, pass: hashPassword(pass), nome, role, criado: new Date().toISOString() });
        saveDB(db);
        return sendJSON(res, 200, { ok: true, user: { id, email, nome, role } });
      }
      if (url === '/api/users/update' && req.method === 'POST') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        if (!isAdmin(a)) return sendJSON(res, 403, { error: 'Apenas o Administrador' });
        const b = await readBody(req); if (!b || !b.id) return sendJSON(res, 400, { error: 'ID em falta' });
        const db = loadDB(); const u = db.users.find(x => x.id === b.id);
        if (!u) return sendJSON(res, 404, { error: 'Conta não encontrada' });
        if (b.nome != null) u.nome = String(b.nome).trim() || u.nome;
        if (b.role != null) u.role = String(b.role).trim() || u.role;
        if (b.password) u.pass = hashPassword(String(b.password));
        saveDB(db);
        return sendJSON(res, 200, { ok: true, user: { id: u.id, email: u.email, nome: u.nome, role: u.role } });
      }
      if (url === '/api/users/delete' && req.method === 'POST') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        if (!isAdmin(a)) return sendJSON(res, 403, { error: 'Apenas o Administrador' });
        const b = await readBody(req); if (!b || !b.id) return sendJSON(res, 400, { error: 'ID em falta' });
        const db = loadDB();
        const u = db.users.find(x => x.id === b.id);
        if (!u) return sendJSON(res, 404, { error: 'Conta não encontrada' });
        if (u.id === a.uid) return sendJSON(res, 400, { error: 'Não pode apagar a sua própria conta' });
        const admins = db.users.filter(x => isAdmin(x));
        if (isAdmin(u) && admins.length <= 1) return sendJSON(res, 400, { error: 'Tem de existir pelo menos um Administrador' });
        db.users = db.users.filter(x => x.id !== b.id);
        saveDB(db);
        return sendJSON(res, 200, { ok: true });
      }

      if (url === '/api/dados' && req.method === 'GET') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const db = loadDB(); const d = db.datasets[WS] || { dados: {}, atualizado: null };
        return sendJSON(res, 200, d);
      }

      if (url === '/api/dados' && req.method === 'PUT') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const b = await readBody(req); if (!b || typeof b.dados !== 'object') return sendJSON(res, 400, { error: 'Payload inválido' });
        _writeQueue = _writeQueue.then(() => {
          const db = loadDB();
          db.datasets[WS] = { dados: b.dados, atualizado: new Date().toISOString() };
          saveDB(db);
        });
        await _writeQueue;
        return sendJSON(res, 200, { ok: true, atualizado: new Date().toISOString() });
      }

      // ----- Sincronização por registo (delta) — espaço partilhado da empresa -----
      if (url === '/api/sync/push' && req.method === 'POST') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const b = await readBody(req); if (!b || !Array.isArray(b.changes)) return sendJSON(res, 400, { error: 'Payload inválido' });
        let resultVer = 0; const applied = [];
        _writeQueue = _writeQueue.then(() => {
          const db = loadDB();
          db.records = db.records || {}; db.seq = db.seq || {};
          db.records[WS] = db.records[WS] || {}; db.seq[WS] = db.seq[WS] || 0;
          const store = db.records[WS];
          b.changes.forEach(ch => {
            if (!ch || ch.registoId == null || !ch.tabela) return;
            const key = ch.tabela + '|' + ch.registoId;
            const ex = store[key];
            const ts = Number(ch.ts) || Date.now();
            if (ex && Number(ex.ts) > ts) return; // mais recente prevalece
            db.seq[WS]++;
            const entry = { tabela: ch.tabela, registoId: ch.registoId, op: ch.op === 'delete' ? 'delete' : 'upsert', dados: ch.op === 'delete' ? null : ch.dados, ts: ts, ver: db.seq[WS], autor: a.email };
            store[key] = entry; applied.push(entry);
          });
          resultVer = db.seq[WS];
          saveDB(db);
        });
        await _writeQueue;
        if (applied.length) sseBroadcast({ ver: resultVer, changes: applied }, b.clientId);
        return sendJSON(res, 200, { ver: resultVer, aplicados: applied.length });
      }

      if (url.indexOf('/api/sync/pull') === 0 && req.method === 'GET') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const since = parseInt((req.url.split('since=')[1] || '0'), 10) || 0;
        const db = loadDB(); const store = (db.records && db.records[WS]) || {}; const ver = (db.seq && db.seq[WS]) || 0;
        const changes = Object.keys(store).map(k => store[k]).filter(e => e.ver > since).sort((x, y) => x.ver - y.ver);
        return sendJSON(res, 200, { ver: ver, changes: changes });
      }

      if (url === '/api/sync/stream' && req.method === 'GET') {
        const q = req.url.split('?')[1] || ''; const params = {}; q.split('&').forEach(kv => { const [k, v] = kv.split('='); params[k] = decodeURIComponent(v || ''); });
        const a = verifyToken(params.token); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        cors(res);
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
        res.write(': ligado\n\n');
        sseAdd(params.clientId || '', res);
        const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { } }, 25000);
        req.on('close', () => { clearInterval(ping); sseRemove(res); });
        return;
      }

      if (url.indexOf('/api/agt/nif/') === 0 && req.method === 'GET') {
        const a = authUser(req); if (!a) return sendJSON(res, 401, { error: 'Sessão inválida' });
        const nif = encodeURIComponent(url.split('/api/agt/nif/')[1] || '');
        if (!AGT_NIF_URL) return sendJSON(res, 501, { error: 'Consulta AGT não configurada (defina AGT_NIF_URL no servidor).' });
        try {
          const upstream = AGT_NIF_URL.indexOf('{nif}') >= 0 ? AGT_NIF_URL.replace('{nif}', nif) : (AGT_NIF_URL + nif);
          const r = await fetch(upstream);
          const j = await r.json();
          return sendJSON(res, 200, j);
        } catch (e) { return sendJSON(res, 502, { error: 'Falha ao contactar a AGT: ' + (e.message || e) }); }
      }

      return sendJSON(res, 404, { error: 'Rota não encontrada' });
    } catch (e) { return sendJSON(res, 500, { error: String(e && e.message || e) }); }
  }

  // -- Site estático --
  serveStatic(req, res);
});

// Migração no arranque: consolida dados antigos (por conta) no espaço partilhado da empresa.
try {
  const _db = loadDB();
  if (!_db._wsMigrado) { migrarParaPartilhado(_db); saveDB(_db); console.log('[migração] dados consolidados no espaço partilhado da empresa.'); }
} catch (e) { console.warn('[migração] aviso:', e && e.message); }

server.listen(PORT, () => console.log('AMDP CRM backend a correr na porta ' + PORT));
module.exports = { server, signToken, verifyToken, hashPassword, verifyPassword };

