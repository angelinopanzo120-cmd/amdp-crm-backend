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
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

// ── Configuração (variáveis de ambiente) ───────────────────────────────────
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data'); // monte um volume persistente aqui
let AUTH_SECRET = process.env.AUTH_SECRET || '';
const ALLOW_REGISTER = process.env.ALLOW_REGISTER === '1'; // registo aberto só se =1 (senão só o 1.º arranque)
const TOKEN_TTL_DAYS = Number(process.env.TOKEN_TTL_DAYS || 30);
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';           // chave do Resend (envio de email)
const MAIL_FROM = process.env.MAIL_FROM || 'AMDP <nao-responder@amdp.ao>';
const BACKUP_DIR = path.join(DATA_DIR, 'backups');   // cópias diárias da base de dados
const BACKUP_KEEP = Number(process.env.BACKUP_KEEP || 5); // quantas manter (menos = menos espaço ocupado)

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
// Segurança: nunca usar um segredo por omissão conhecido. Se AUTH_SECRET não vier do
// ambiente, gera-se um segredo forte e guarda-se no volume (persiste entre reinícios).
if (!AUTH_SECRET || AUTH_SECRET === 'troque-este-segredo-em-producao') {
  const _sf = path.join(DATA_DIR, '.authsecret');
  try {
    if (fs.existsSync(_sf)) AUTH_SECRET = String(fs.readFileSync(_sf, 'utf8')).trim();
    if (!AUTH_SECRET) { AUTH_SECRET = crypto.randomBytes(48).toString('base64url'); fs.writeFileSync(_sf, AUTH_SECRET, { mode: 0o600 }); }
    console.warn('[seguranca] AUTH_SECRET não definido nas variáveis — a usar um segredo gerado e guardado em ' + _sf + '. Para controlo total, defina AUTH_SECRET no Railway.');
  } catch (e) { AUTH_SECRET = crypto.randomBytes(48).toString('base64url'); console.warn('[seguranca] AUTH_SECRET gerado em memória (não foi possível persistir): ' + (e && e.message ? e.message : e)); }
}
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
CREATE TABLE IF NOT EXISTS files (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  nome       TEXT,
  tipo       TEXT,
  dados      BLOB,
  criado_em  TEXT
);
CREATE TABLE IF NOT EXISTS pass_reset (
  user_id    TEXT PRIMARY KEY,
  code_hash  TEXT,
  expira     INTEGER,
  tentativas INTEGER NOT NULL DEFAULT 0,
  criado     INTEGER
);
`);

// ── Migrações leves (colunas novas em instalações já existentes) ────────────
try { db.exec("ALTER TABLE users ADD COLUMN last_login TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN sess_ver INTEGER NOT NULL DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN areas TEXT"); } catch (e) {}        // divisões permitidas (JSON) — fonte única de verdade
try { db.exec("ALTER TABLE users ADD COLUMN perfil_key TEXT"); } catch (e) {}   // perfil (administrador/comercial/...)
try { db.exec("ALTER TABLE files ADD COLUMN r2url TEXT"); } catch (e) {}   // ficheiro já movido para o R2 (dados fica NULL)

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

// ── Segurança de autenticação: força da palavra-passe + travão de tentativas ─
function senhaFraca(pw){ pw=String(pw||''); return pw.length<8 || !/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw); }
// ── Cópia de segurança automática da base de dados ──────────────────────────
function _freeBytes(){ try{ var s = fs.statfsSync(DATA_DIR); return s.bavail * s.bsize; }catch(e){ return -1; } }
function fazerBackup(){
  try{
    if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    // PRUNE PRIMEIRO: apaga cópias antigas ANTES de copiar — assim, mesmo com o disco quase
    // cheio, liberta-se espaço (um disco cheio impediria a limpeza se ela viesse depois).
    try{ var _fl0 = fs.readdirSync(BACKUP_DIR).filter(function(f){ return /^amdp-.*\.db$/.test(f); }).sort(); while(_fl0.length >= Math.max(1, BACKUP_KEEP)){ var _old0 = _fl0.shift(); try{ fs.unlinkSync(path.join(BACKUP_DIR, _old0)); }catch(e){} } }catch(e){}
    try{ db.exec('PRAGMA wal_checkpoint(TRUNCATE);'); }catch(e){}   // junta o WAL ao ficheiro principal
    const src = path.join(DATA_DIR, 'amdp.db');
    if(!fs.existsSync(src)) return null;
    var _dbSize = 0; try{ _dbSize = fs.statSync(src).size; }catch(e){}
    // Não criar a cópia se não houver espaço livre suficiente — uma cópia ocupa o
    // tamanho da base, e encher o volume impediria o sistema de GRAVAR dados reais.
    var _free = _freeBytes();
    if(_free >= 0 && _dbSize > 0 && _free < _dbSize * 1.3){
      console.warn('[backup] espaço insuficiente (' + Math.round(_free/1048576) + ' MB livres, base ' + Math.round(_dbSize/1048576) + ' MB) — cópia adiada para não encher o volume.');
      return null;
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const dest = path.join(BACKUP_DIR, 'amdp-' + stamp + '.db');
    fs.copyFileSync(src, dest);
    let files = fs.readdirSync(BACKUP_DIR).filter(f => /^amdp-.*\.db$/.test(f)).sort();
    while(files.length > BACKUP_KEEP){ const old = files.shift(); try{ fs.unlinkSync(path.join(BACKUP_DIR, old)); }catch(e){} }
    console.log('[backup] criado ' + dest + ' (' + files.length + ' cópias)');
    return dest;
  }catch(e){ console.warn('[backup] falhou:', e && e.message ? e.message : e); return null; }
}
const REGRA_SENHA = 'Palavra-passe fraca: use pelo menos 8 caracteres, com letras e números.';
// ── Envio de email (Resend, por HTTPS) — usado na recuperação de palavra-passe ──
function enviarEmailResend(para, assunto, html) {
  return new Promise((resolve, reject) => {
    if (!RESEND_API_KEY) { reject(new Error('RESEND_API_KEY em falta')); return; }
    const payload = JSON.stringify({ from: MAIL_FROM, to: [para], subject: assunto, html: html });
    const rq = https.request({ host: 'api.resend.com', path: '/emails', method: 'POST', headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (r) => {
      let d = ''; r.on('data', c => d += c);
      r.on('end', () => { (r.statusCode >= 200 && r.statusCode < 300) ? resolve(true) : reject(new Error('Resend ' + r.statusCode + ' ' + d.slice(0, 200))); });
    });
    rq.on('error', reject); rq.write(payload); rq.end();
  });
}
const _resetThrottle = new Map(); // email -> ts do último pedido (anti-spam)
const _loginTent = new Map(); // chave(email|ip) -> {fails, until}
function _loginChave(req, email){ const xf=String(req.headers['x-forwarded-for']||'').split(',')[0].trim(); const ip=xf||(req.socket&&req.socket.remoteAddress)||''; return String(email||'')+'|'+ip; }
function _loginBloqueado(k){ const r=_loginTent.get(k); if(r&&r.until&&Date.now()<r.until) return Math.ceil((r.until-Date.now())/60000); return 0; }
function _loginFalhou(k){ const r=_loginTent.get(k)||{fails:0,until:0}; r.fails=(r.fails||0)+1; if(r.fails>=5){ r.until=Date.now()+15*60*1000; r.fails=0; } _loginTent.set(k,r); }
function _loginOk(k){ _loginTent.delete(k); }

// ── Armazenamento de ficheiros na nuvem (Cloudflare R2, opcional) ───────────
// Se as 5 variaveis R2_* estiverem definidas, os comprovativos vao para o R2.
// Caso contrario, ficam guardados no proprio servidor (tabela files) — que ja
// e "a nuvem" do ponto de vista do utilizador (acessivel em qualquer aparelho).
const R2 = {
  account:    process.env.R2_ACCOUNT_ID || '',
  bucket:     process.env.R2_BUCKET || '',
  // Aceita os dois esquemas de nomes (os originais e os que já possas ter no Railway).
  accessKey:  process.env.R2_ACCESS_KEY_ID || process.env.R2_ACCESS_KEY || '',
  secretKey:  process.env.R2_SECRET_ACCESS_KEY || process.env.R2_SECRET || '',
  publicBase: String(process.env.R2_PUBLIC_BASE || process.env.R2_PUBLIC_URL || '').replace(/\/+$/, ''),
  endpoint:   String(process.env.R2_ENDPOINT || '').replace(/\/+$/, '')
};
// Deriva o Account ID a partir do endpoint, quando só o endpoint foi fornecido.
if (!R2.account && R2.endpoint) { const _m = R2.endpoint.match(/^https?:\/\/([^.]+)\.r2\.cloudflarestorage\.com/i); if (_m) R2.account = _m[1]; }
// Host S3 do R2 (sem protocolo): usa o endpoint se existir, senão constrói do account.
R2.host = R2.endpoint ? R2.endpoint.replace(/^https?:\/\//, '') : (R2.account ? R2.account + '.r2.cloudflarestorage.com' : '');
function r2Ativo() { return !!(R2.host && R2.bucket && R2.accessKey && R2.secretKey && R2.publicBase); }
function _sha256hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function _hmac(key, str) { return crypto.createHmac('sha256', key).update(str, 'utf8').digest(); }
function r2Put(objKey, buf, contentType) {
  return new Promise((resolve, reject) => {
    try {
      const host = R2.host;
      const region = 'auto', service = 's3';
      const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
      const dateStamp = amzDate.slice(0, 8);
      const canonicalUri = '/' + R2.bucket + '/' + objKey.split('/').map(encodeURIComponent).join('/');
      const payloadHash = _sha256hex(buf);
      const canonicalHeaders = 'host:' + host + '\n' + 'x-amz-content-sha256:' + payloadHash + '\n' + 'x-amz-date:' + amzDate + '\n';
      const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
      const canonicalRequest = 'PUT\n' + canonicalUri + '\n\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payloadHash;
      const scope = dateStamp + '/' + region + '/' + service + '/aws4_request';
      const stringToSign = 'AWS4-HMAC-SHA256\n' + amzDate + '\n' + scope + '\n' + _sha256hex(Buffer.from(canonicalRequest, 'utf8'));
      const kDate = _hmac('AWS4' + R2.secretKey, dateStamp);
      const kRegion = _hmac(kDate, region);
      const kService = _hmac(kRegion, service);
      const kSigning = _hmac(kService, 'aws4_request');
      const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');
      const authorization = 'AWS4-HMAC-SHA256 Credential=' + R2.accessKey + '/' + scope +
        ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
      const rq = https.request({
        host: host, method: 'PUT', path: canonicalUri,
        headers: {
          'Authorization': authorization,
          'x-amz-content-sha256': payloadHash,
          'x-amz-date': amzDate,
          'Content-Type': contentType || 'application/octet-stream',
          'Content-Length': buf.length
        }
      }, (r) => {
        let d = ''; r.on('data', c => d += c);
        r.on('end', () => { (r.statusCode >= 200 && r.statusCode < 300) ? resolve(R2.publicBase + '/' + objKey) : reject('R2 ' + r.statusCode + ' ' + d.slice(0, 200)); });
      });
      rq.on('error', reject); rq.write(buf); rq.end();
    } catch (e) { reject(e); }
  });
}
// Leitura ASSINADA de um objeto do R2 (não precisa de bucket público). Chama onResponse(r2res)
// com a resposta HTTP do R2 (que se pode encaminhar diretamente ao cliente) ou onError(e).
function r2GetStream(objKey, onResponse, onError) {
  try {
    const host = R2.host, region = 'auto', service = 's3';
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);
    const canonicalUri = '/' + R2.bucket + '/' + objKey.split('/').map(encodeURIComponent).join('/');
    const payloadHash = _sha256hex(Buffer.from(''));
    const canonicalHeaders = 'host:' + host + '\n' + 'x-amz-content-sha256:' + payloadHash + '\n' + 'x-amz-date:' + amzDate + '\n';
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalRequest = 'GET\n' + canonicalUri + '\n\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + payloadHash;
    const scope = dateStamp + '/' + region + '/' + service + '/aws4_request';
    const stringToSign = 'AWS4-HMAC-SHA256\n' + amzDate + '\n' + scope + '\n' + _sha256hex(Buffer.from(canonicalRequest, 'utf8'));
    const kDate = _hmac('AWS4' + R2.secretKey, dateStamp), kRegion = _hmac(kDate, region), kService = _hmac(kRegion, service), kSigning = _hmac(kService, 'aws4_request');
    const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');
    const authorization = 'AWS4-HMAC-SHA256 Credential=' + R2.accessKey + '/' + scope + ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
    const rq = https.request({ host: host, method: 'GET', path: canonicalUri, headers: { 'Authorization': authorization, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate } }, onResponse);
    rq.on('error', onError); rq.setTimeout(20000, function () { try { rq.destroy(); } catch (e) {} onError(new Error('timeout')); }); rq.end();
  } catch (e) { onError(e); }
}
function _baseUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = req.headers['host'] || 'localhost';
  return proto + '://' + host;
}

// ── Acesso a dados (statements preparados) ──────────────────────────────────
const Q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)'),
  userById: db.prepare('SELECT * FROM users WHERE id=?'),
  usersByTenant: db.prepare('SELECT id,email,nome,role,ativo,last_login,areas,perfil_key FROM users WHERE tenant_id=? ORDER BY criado_em'),
  setLastLogin: db.prepare('UPDATE users SET last_login=? WHERE id=?'),
  bumpSess: db.prepare('UPDATE users SET sess_ver=COALESCE(sess_ver,0)+1 WHERE id=? AND tenant_id=?'),
  insTenant: db.prepare('INSERT INTO tenants(id,nome,ver,criado_em) VALUES(?,?,0,?)'),
  countTenants: db.prepare('SELECT COUNT(*) AS n FROM tenants'),
  upsertReset: db.prepare('INSERT INTO pass_reset(user_id,code_hash,expira,tentativas,criado) VALUES(?,?,?,0,?) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash, expira=excluded.expira, tentativas=0, criado=excluded.criado'),
  getReset: db.prepare('SELECT * FROM pass_reset WHERE user_id=?'),
  bumpResetTent: db.prepare('UPDATE pass_reset SET tentativas=tentativas+1 WHERE user_id=?'),
  delReset: db.prepare('DELETE FROM pass_reset WHERE user_id=?'),
  insUser: db.prepare('INSERT INTO users(id,tenant_id,email,pass_hash,nome,role,ativo,criado_em) VALUES(?,?,?,?,?,?,1,?)'),
  updUserPass: db.prepare('UPDATE users SET pass_hash=? WHERE id=?'),
  updUser: db.prepare('UPDATE users SET nome=?, role=? WHERE id=? AND tenant_id=?'),
  setUserAreas: db.prepare('UPDATE users SET areas=?, perfil_key=? WHERE id=? AND tenant_id=?'),
  usersAreasNull: db.prepare("SELECT id,email FROM users WHERE tenant_id=? AND (areas IS NULL OR areas='')"),
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
  insFile: db.prepare('INSERT INTO files(id,tenant_id,nome,tipo,dados,criado_em) VALUES(?,?,?,?,?,?)'),
  getFile: db.prepare('SELECT nome,tipo,dados,tenant_id,r2url FROM files WHERE id=?'),
  // Migração de ficheiros da base para o R2
  filesBlobCount: db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(dados)),0) AS bytes FROM files WHERE dados IS NOT NULL'),
  filesBlobBatch: db.prepare('SELECT id,tenant_id,nome,tipo,dados FROM files WHERE dados IS NOT NULL LIMIT ?'),
  fileSetR2: db.prepare('UPDATE files SET r2url=?, dados=NULL WHERE id=?'),
};

// Transação simples (node:sqlite não tem helper próprio).
function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) { } throw e; }
}

// Aplica um lote de alterações de forma ATÓMICA e devolve a nova versão.
function applyChanges(tenantId, clientId, autor, changes, me) {
  const areas = me ? visAreas(me) : 'all';
  const idx = (areas === 'all') ? null : buildIdx(tenantId);
  const podeApagar = me ? podeEliminarSrv(me) : true;
  return tx(() => {
    const row = Q.tenantVer.get(tenantId);
    let ver = Number((row && row.ver) || 0);
    const aplicadas = [];
    for (const ch of changes) {
      if (!ch || !ch.tabela || ch.registoId == null) continue;
      const del = ch.op === 'delete' ? 1 : 0;
      // ELIMINAÇÃO só pelo Administrador. O pedido de um não-administrador é
      // registado no cliente (tabela pedidos_eliminacao) e só é aplicado quando
      // o Administrador o aprova — por isso aqui uma eliminação não autorizada é ignorada.
      if (del && !podeApagar && ch.tabela !== 'pedidos_eliminacao') continue;
      // ESCRITA só na própria divisão: um utilizador restrito não grava registos de outra área.
      if (!del && areas !== 'all' && !recVisivel(areas, ch.tabela, ch.dados, idx)) continue;
      ver += 1;
      Q.upsertRec.run(tenantId, String(ch.tabela), String(ch.registoId),
        del ? null : JSON.stringify(ch.dados), del, ver, clientId || null, autor || null, now());
      Q.insAudit.run(tenantId, autor || '', del ? 'eliminar' : 'alterar', String(ch.tabela), String(ch.registoId), now());
      aplicadas.push(ch);
    }
    Q.bumpTenant.run(ver, tenantId);
    return { ver, aplicadas };
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
  const allPayload = 'data: ' + JSON.stringify({ changes, ver }) + '\n\n';
  let idx = null, idxBuilt = false;
  for (const c of set) {
    if (originClientId && c.clientId === originClientId) continue; // não devolver ao próprio emissor
    let payload = allPayload;
    // Isolamento de divisões em tempo real: um utilizador restrito só recebe as
    // alterações das suas divisões (as eliminações passam sempre, são inofensivas).
    if (c.areas && c.areas !== 'all') {
      if (!idxBuilt) { try { idx = buildIdx(tenantId); } catch (e) { idx = null; } idxBuilt = true; }
      const vis = changes.filter(ch => (ch.op === 'delete') || recVisivel(c.areas, ch.tabela, ch.dados, idx));
      if (!vis.length) continue;
      payload = 'data: ' + JSON.stringify({ changes: vis, ver }) + '\n\n';
    }
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-File-Name');
  res.setHeader('Access-Control-Max-Age', '86400');
  // Cabeçalhos de segurança (defesa em profundidade) em todas as respostas do servidor.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 25 * 1024 * 1024) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
function readRaw(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0; const lim = maxBytes || 30 * 1024 * 1024;
    req.on('data', c => { total += c.length; if (total > lim) { req.destroy(); reject(new Error('too-large')); return; } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
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
  if (Number(p.sv || 0) !== Number(u.sess_ver || 0)) return null; // sessão terminada pelo administrador / palavra-passe alterada
  return u; // {id,tenant_id,email,nome,role,...}
}
function tokenForUser(u) {
  return signToken({ uid: u.id, tid: u.tenant_id, role: u.role, sv: Number(u.sess_ver || 0), exp: Date.now() + TOKEN_TTL_DAYS * 864e5 });
}

// ── Isolamento de divisões ao nível do SERVIDOR ─────────────────────────────
// Um utilizador restrito a certas divisões NUNCA recebe (nem no pull, nem no
// snapshot, nem no tempo-real) registos de divisões a que não tem acesso.
// Princípio de segurança: na dúvida, o registo é tratado como COMUM (visível) —
// assim nunca se escondem dados necessários; só se retêm os que têm, de forma
// inequívoca, uma divisão concreta a que o utilizador não pertence.
const _SETOR_KEYS = ['geral', 'motors', 'construcoes', 'saude', 'procurement', 'alimentar'];
const _DIV2SETOR = {
  'AMDP Motors': 'motors',
  'Construções & Engenharia': 'construcoes',
  'AMDP Saúde': 'saude',
  'Procurement': 'procurement',
  'Distribuição Alimentar': 'alimentar',
  'Geral / AMDP': 'geral',
  'Múltiplas': 'geral'
};
const _TRANSVERSAIS = { consulta: 1, contabilidade: 1, rh: 1 };
function _perfilKeySrv(role) {
  const r = String(role || '').toLowerCase();
  if (r.indexOf('admin') >= 0) return 'administrador';
  if (r.indexOf('contab') >= 0) return 'contabilidade';
  if (r.indexOf('human') >= 0 || r === 'rh') return 'rh';
  if (r.indexOf('ofic') >= 0) return 'oficina';
  if (r.indexOf('consulta') >= 0 || r.indexOf('leitura') >= 0) return 'consulta';
  if (r.indexOf('comerc') >= 0) return 'comercial';
  return 'administrador';
}
// Áreas guardadas na própria conta (users.areas, JSON). Null/erro → null.
function _userAreasCol(u) {
  try { if (u && u.areas != null && u.areas !== '') { const a = JSON.parse(u.areas); return (a === 'all' || Array.isArray(a)) ? a : null; } } catch (e) {}
  return null;
}
// Grava as áreas e o perfil de uma conta (administrador → 'all'; senão só chaves válidas).
function _guardarAreas(tenantId, userId, role, areas) {
  const pk = _perfilKeySrv(role);
  let val;
  if (pk === 'administrador') val = 'all';
  else if (areas === 'all') val = 'all';
  else if (Array.isArray(areas)) val = areas.filter(function (k) { return _SETOR_KEYS.indexOf(k) >= 0; });
  else val = [];
  try { Q.setUserAreas.run(JSON.stringify(val), pk, userId, tenantId); } catch (e) {}
}
const _TAB_SETOR = { facturas: 1, proformas: 1, orcamentos: 1, artigos: 1, recorrentes: 1, requisicoes: 1, consultas: 1, ordenscompra: 1 };
const _TAB_DIVISAO = { leads: 1, propostas: 1, contratos: 1, fornecedores: 1 };
const _qPerm = db.prepare("SELECT dados FROM records WHERE tenant_id=? AND tabela='utilizadores' AND registo_id=? AND deleted=0");
const _qUtilAll = db.prepare("SELECT registo_id,dados FROM records WHERE tenant_id=? AND tabela='utilizadores' AND deleted=0");
const _qRecsTab = db.prepare("SELECT registo_id,dados FROM records WHERE tenant_id=? AND tabela=? AND deleted=0");

function _permRecordBy(tenantId, email) {
  try {
    email = String(email || '').toLowerCase();
    let row = _qPerm.get(tenantId, 'perm:' + email);
    if (!row && email) {
      const rows = _qUtilAll.all(tenantId);
      for (const r of rows) { try { const d = JSON.parse(r.dados); if (String(d.user || '').toLowerCase() === email) { row = { dados: r.dados }; break; } } catch (e) {} }
    }
    return row ? JSON.parse(row.dados) : null;
  } catch (e) { return null; }
}
function _permRecord(me) { return _permRecordBy(me.tenant_id, me.email); }
// Devolve 'all' (vê tudo) ou um array de chaves de divisão permitidas.
function visAreas(me) {
  if (isAdmin(me.role)) return 'all';
  const pk = String(me.perfil_key || _perfilKeySrv(me.role) || '').toLowerCase();
  if (pk === 'administrador') return 'all';
  if (_TRANSVERSAIS[pk]) return 'all';
  // 1) Fonte de verdade: as áreas guardadas na própria conta.
  const ac = _userAreasCol(me);
  if (ac === 'all') return 'all';
  if (Array.isArray(ac)) return ac.filter(function (k) { return _SETOR_KEYS.indexOf(k) >= 0; });
  // 2) Compatibilidade: registo de permissões antigo (até a conta ser gravada de novo).
  const perm = _permRecord(me);
  if (perm) {
    const pk2 = String(perm.perfilKey || '').toLowerCase();
    if (pk2 === 'administrador' || isAdmin(perm.role)) return 'all';
    if (_TRANSVERSAIS[pk2]) return 'all';
    if (perm.areas === 'all') return 'all';
    if (Array.isArray(perm.areas)) return perm.areas.filter(function (k) { return _SETOR_KEYS.indexOf(k) >= 0; });
  }
  return [];
}
// Índice de divisões das tabelas-pai (cliente/fornecedor/artigo), para resolver
// a divisão de contas-correntes e movimentos de stock. Só se constrói para
// utilizadores restritos (o administrador não filtra nada).
function buildIdx(tenantId) {
  const idx = { cli: {}, forn: {}, art: {} };
  try {
    for (const r of _qRecsTab.all(tenantId, 'clientes')) { try { const d = JSON.parse(r.dados); let k = _DIV2SETOR[d.divisao]; if ((!k || k === 'geral') && Array.isArray(d.areas) && d.areas.length === 1) k = d.areas[0]; idx.cli[String(d.id != null ? d.id : r.registo_id)] = k || 'geral'; } catch (e) {} }
    for (const r of _qRecsTab.all(tenantId, 'fornecedores')) { try { const d = JSON.parse(r.dados); idx.forn[String(d.id != null ? d.id : r.registo_id)] = _DIV2SETOR[d.divisao] || 'geral'; } catch (e) {} }
    for (const r of _qRecsTab.all(tenantId, 'artigos')) { try { const d = JSON.parse(r.dados); idx.art[String(d.id != null ? d.id : r.registo_id)] = (d.setor && _SETOR_KEYS.indexOf(d.setor) >= 0) ? d.setor : 'geral'; } catch (e) {} }
  } catch (e) {}
  return idx;
}
// Divisão (chave) de um registo, ou null/'geral' se for comum/partilhado.
function recSetor(tabela, dados, idx) {
  if (!dados || typeof dados !== 'object') return null;
  if (_TAB_SETOR[tabela]) { const s = dados.setor; return (s && _SETOR_KEYS.indexOf(s) >= 0) ? s : 'geral'; }
  if (_TAB_DIVISAO[tabela]) { return _DIV2SETOR[dados.divisao] || 'geral'; }
  if (tabela === 'viaturas' || tabela === 'ordens' || tabela === 'avaliacoes') return 'motors';
  if (tabela === 'obras') return 'construcoes';
  if (tabela === 'contacorrente') { if (dados.setor && _SETOR_KEYS.indexOf(dados.setor) >= 0 && dados.setor !== 'geral') return dados.setor; return (idx && idx.cli[String(dados.clienteId)]) || 'geral'; }
  if (tabela === 'fcorrente') { return (idx && idx.forn[String(dados.fornId != null ? dados.fornId : dados.fornecedorId)]) || 'geral'; }
  if (tabela === 'stockmovs') { return (idx && idx.art[String(dados.artigoId)]) || 'geral'; }
  return null;            // qualquer outra tabela: comum (config, séries, utilizadores, etc.)
}
// Só o Administrador (ou perfil marcado como tal) pode ELIMINAR registos.
// Os perfis transversais (contabilidade, etc.) veem tudo, mas NÃO eliminam.
function podeEliminarSrv(me) {
  if (isAdmin(me.role)) return true;
  const perm = _permRecord(me);
  if (perm && (String(perm.perfilKey || '').toLowerCase() === 'administrador' || isAdmin(perm.role) || perm.podeEliminar === true)) return true;
  return false;
}
// Um registo é visível para um utilizador com estas áreas?
function recVisivel(areasUser, tabela, dados, idx) {
  if (areasUser === 'all') return true;
  if (tabela === 'clientes') {
    const as = Array.isArray(dados && dados.areas) ? dados.areas.slice() : [];
    const dk = _DIV2SETOR[dados && dados.divisao]; if (dk && dk !== 'geral' && as.indexOf(dk) < 0) as.push(dk);
    if (!as.length) return true;                       // sem divisão → comum
    return as.some(a => areasUser.indexOf(a) >= 0);
  }
  const s = recSetor(tabela, dados, idx);
  if (s == null || s === '' || s === 'geral') return true;   // comum/partilhado
  return areasUser.indexOf(s) >= 0;
}

// ── Migração (uma vez): preenche users.areas a partir dos registos de permissões antigos ──
try {
  const _tns = db.prepare('SELECT id FROM tenants').all();
  let _mg = 0;
  for (const t of _tns) {
    const us = Q.usersAreasNull.all(t.id);
    for (const u of us) {
      const full = Q.userById.get(u.id);
      const perm = _permRecordBy(t.id, u.email);
      const role = (full && full.role) || (perm && perm.role) || 'Comercial';
      let areas = (perm && perm.areas !== undefined) ? perm.areas : [];
      _guardarAreas(t.id, u.id, role, areas === 'all' ? 'all' : (Array.isArray(areas) ? areas : []));
      _mg++;
    }
  }
  if (_mg) console.log('[migracao] users.areas preenchido em ' + _mg + ' conta(s)');
} catch (e) { console.warn('[migracao areas]', e && e.message ? e.message : e); }

// ── Servidor ────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const u = urlOf(req);
  const p = u.pathname;
  try {
    // — Saúde / diagnóstico (abra este endereço no browser para verificar o servidor) —
    if (p === '/' || p === '/api/health') {
      var _dbB = 0, _bkB = 0, _bkN = 0, _escritaOk = false;
      try { _dbB = fs.statSync(path.join(DATA_DIR, 'amdp.db')).size; } catch (e) {}
      try { if (fs.existsSync(BACKUP_DIR)) { var _fl = fs.readdirSync(BACKUP_DIR).filter(function (f) { return /^amdp-.*\.db$/.test(f); }); _bkN = _fl.length; _fl.forEach(function (f) { try { _bkB += fs.statSync(path.join(BACKUP_DIR, f)).size; } catch (e) {} }); } } catch (e) {}
      try { var _tf = path.join(DATA_DIR, '.writetest'); fs.writeFileSync(_tf, 'ok'); fs.unlinkSync(_tf); _escritaOk = true; } catch (e) { _escritaOk = false; }
      var _mb = function (n) { return Math.round(n / 1048576 * 10) / 10; };
      var _freeB = _freeBytes();
      return send(res, 200, {
        ok: true, servico: 'AMDP sync', versao: 'Z226', tempo: now(),
        escrita_ok: _escritaOk,                      // false = disco cheio/sem permissão (os dados NÃO estão a ser guardados)
        espaco_livre_mb: _freeB >= 0 ? _mb(_freeB) : 'desconhecido',
        base_dados_mb: _mb(_dbB), copias: _bkN, copias_mb: _mb(_bkB), copias_max: BACKUP_KEEP,
        ficheiros_na_base: r2Ativo() ? 'não (vão para o R2)' : 'sim (ocupam espaço na base)',
        r2: { ativo: r2Ativo(), bucket: !!R2.bucket, host: R2.host || '(em falta)', url_publico: !!R2.publicBase, chaves: !!(R2.accessKey && R2.secretKey) },
        aviso: _escritaOk ? undefined : 'O SERVIDOR NÃO CONSEGUE GRAVAR — o volume do Railway está cheio. Aumente o volume (Redimensionar) e/ou reduza as cópias de segurança (BACKUP_KEEP) e ligue o R2 para os comprovativos.'
      });
    }

    // — Registo (cria empresa + administrador) —
    if (p === '/api/auth/register' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!email || !pass) return send(res, 400, { error: 'Indique email e palavra-passe' });
      if (senhaFraca(pass)) return send(res, 400, { error: REGRA_SENHA });
      // Segurança: registo só no 1.º arranque (sem empresas) ou se ALLOW_REGISTER=1.
      let _nT = 1; try { _nT = Q.countTenants.get().n; } catch (e) {}
      if (!ALLOW_REGISTER && _nT > 0) return send(res, 403, { error: 'Registo fechado. Peça ao Administrador para criar a sua conta.' });
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
      const chave = _loginChave(req, email);
      const espera = _loginBloqueado(chave);
      if (espera) return send(res, 429, { error: 'Demasiadas tentativas falhadas. Tente novamente dentro de ' + espera + ' min.' });
      const user = Q.userByEmail.get(email);
      if (!user || Number(user.ativo) === 0 || !verifyPassword(pass, user.pass_hash)) { _loginFalhou(chave); return send(res, 401, { error: 'Email ou palavra-passe incorrectos' }); }
      _loginOk(chave);
      try { Q.setLastLogin.run(now(), user.id); } catch (e) {}
      // Devolve já as ÁREAS (divisões) permitidas e o perfil, para o cliente não
      // depender de sincronização nenhuma no instante do login.
      let _va = 'all';
      try { _va = visAreas(user); } catch (e) {}
      return send(res, 200, { token: tokenForUser(user), nome: user.nome, role: user.role, email: user.email, perfilKey: user.perfil_key || _perfilKeySrv(user.role), areas: Array.isArray(_va) ? _va : undefined });
    }

    // — Trocar a própria palavra-passe —
    if (p === '/api/auth/password' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      if (!verifyPassword(String(b.currentPassword || ''), me.pass_hash)) return send(res, 400, { error: 'Palavra-passe actual incorrecta' });
      if (senhaFraca(b.newPassword)) return send(res, 400, { error: REGRA_SENHA });
      Q.updUserPass.run(hashPassword(String(b.newPassword)), me.id);
      return send(res, 200, { ok: true });
    }

    // — Snapshot completo (reserva/compatibilidade) —
    if (p === '/api/dados' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const rows = Q.allRecs.all(me.tenant_id);
      const _areas = visAreas(me);
      const _idx = (_areas === 'all') ? null : buildIdx(me.tenant_id);
      const dados = {};
      for (const r of rows) {
        let _obj; try { _obj = JSON.parse(r.dados); } catch (e) { continue; }
        if (!recVisivel(_areas, r.tabela, _obj, _idx)) continue;   // isolamento de divisões
        const key = 'amdp_crm_' + r.tabela;
        if (!dados[key]) dados[key] = [];
        dados[key].push(_obj);
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
      const r = applyChanges(me.tenant_id, null, me.nome, changes, me);
      if (r.aplicadas.length) broadcast(me.tenant_id, null, r.aplicadas.map(c => ({ tabela: c.tabela, registoId: c.registoId, op: 'upsert', dados: c.dados })), r.ver);
      return send(res, 200, { ok: true, ver: r.ver });
    }

    // — Sincronização incremental: ENVIAR —
    if (p === '/api/sync/push' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const b = await readBody(req);
      const changes = Array.isArray(b.changes) ? b.changes : [];
      const clientId = b.clientId || null;
      const r = applyChanges(me.tenant_id, clientId, me.nome, changes, me);
      if (r.aplicadas.length) broadcast(me.tenant_id, clientId, r.aplicadas.map(c => ({
        tabela: c.tabela, registoId: c.registoId, op: c.op === 'delete' ? 'delete' : 'upsert', dados: c.op === 'delete' ? null : c.dados,
      })), r.ver);
      return send(res, 200, { ver: r.ver });
    }

    // — Sincronização incremental: DESCARREGAR (catch-up) —
    if (p === '/api/sync/pull' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const since = Number(u.searchParams.get('since') || 0);
      const rows = Q.changesSince.all(me.tenant_id, since);
      const _areas = visAreas(me);
      const _idx = (_areas === 'all') ? null : buildIdx(me.tenant_id);
      const changes = [];
      for (const r of rows) {
        const _obj = r.deleted ? null : (() => { try { return JSON.parse(r.dados); } catch (e) { return null; } })();
        // Eliminações passam sempre (inofensivas: o cliente nem tem o registo).
        // Alterações só passam se a divisão for visível para este utilizador.
        if (!r.deleted && !recVisivel(_areas, r.tabela, _obj, _idx)) continue;
        changes.push({ tabela: r.tabela, registoId: r.registo_id, op: r.deleted ? 'delete' : 'upsert', dados: _obj });
      }
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
      const entry = { res, clientId, areas: visAreas(me) };   // áreas p/ filtrar a difusão em tempo real
      streams.get(me.tenant_id).add(entry);
      const ka = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { } }, 25000);
      req.on('close', () => { clearInterval(ka); const s = streams.get(me.tenant_id); if (s) s.delete(entry); });
      return; // mantém a ligação aberta
    }

    // — Utilizadores (só Administrador) —
    if (p === '/api/users' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      return send(res, 200, { users: Q.usersByTenant.all(me.tenant_id).map(x => {
        // ÁREAS e PERFIL de cada conta: primeiro da própria conta (fonte de verdade),
        // com recurso ao registo de permissões antigo enquanto a conta não for regravada.
        let _areas = _userAreasCol(x), _pk = x.perfil_key || _perfilKeySrv(x.role), _role = x.role;
        if (_areas == null) { try { const _pm = _permRecordBy(me.tenant_id, x.email); if (_pm) { if (_pm.areas !== undefined) _areas = _pm.areas; if (_pm.perfilKey) _pk = _pm.perfilKey; } } catch (e) {} }
        return { id: x.id, email: x.email, nome: x.nome, role: _role, perfilKey: _pk, areas: _areas, ativo: Number(x.ativo) !== 0, last_login: x.last_login || null };
      }) });
    }
    if (p === '/api/users/create' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!email || !pass) return send(res, 400, { error: 'Email e palavra-passe obrigatórios' });
      if (senhaFraca(pass)) return send(res, 400, { error: REGRA_SENHA });
      if (Q.userByEmail.get(email)) return send(res, 409, { error: 'Email já existe' });
      const _uid = newId('u_');
      Q.insUser.run(_uid, me.tenant_id, email, hashPassword(pass), String(b.nome || email.split('@')[0]), String(b.role || 'Comercial'), now());
      _guardarAreas(me.tenant_id, _uid, String(b.role || 'Comercial'), b.areas);   // divisões permitidas
      return send(res, 200, { ok: true });
    }
    if (p === '/api/users/update' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const target = Q.userById.get(String(b.id || ''));
      if (!target || target.tenant_id !== me.tenant_id) return send(res, 404, { error: 'Conta não encontrada' });
      const _novoRole = String(b.role || target.role);
      Q.updUser.run(String(b.nome || target.nome), _novoRole, target.id, me.tenant_id);
      if (b.areas !== undefined) _guardarAreas(me.tenant_id, target.id, _novoRole, b.areas);   // atualiza as divisões permitidas
      if (b.password) {
        if (senhaFraca(b.password)) return send(res, 400, { error: REGRA_SENHA });
        Q.updUserPass.run(hashPassword(String(b.password)), target.id);
        Q.bumpSess.run(target.id, me.tenant_id); // a nova palavra-passe termina as sessões antigas dessa conta
      }
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

    // — Ficheiros / comprovativos na nuvem —
    if (p === '/api/files' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const MAX = 30 * 1024 * 1024; // 30 MB
      const cthdr = String(req.headers['content-type'] || '');
      let buf, ctype, nome;
      if (cthdr.indexOf('application/json') === 0) {
        // Modo antigo: JSON com dataBase64 (imagens pequenas)
        const b = await readBody(req);
        const raw = String(b.dataBase64 || b.data || '');
        const mm = raw.match(/^data:([^;,]*)(;base64)?,(.*)$/);
        ctype = (mm && mm[1]) || String(b.type || 'application/octet-stream');
        try { buf = Buffer.from(mm ? mm[3] : raw, 'base64'); } catch (e) { return send(res, 400, { error: 'Ficheiro inválido' }); }
        nome = String(b.name || 'ficheiro');
      } else {
        // Modo binário: o corpo do pedido É o ficheiro (sem base64) — ideal para PDFs grandes
        try { buf = await readRaw(req, MAX); }
        catch (e) { return send(res, 413, { error: 'Ficheiro demasiado grande (máx. 30 MB)' }); }
        ctype = cthdr || 'application/octet-stream';
        try { nome = decodeURIComponent(String(req.headers['x-file-name'] || 'ficheiro')); } catch (e) { nome = 'ficheiro'; }
      }
      if (!buf || !buf.length) return send(res, 400, { error: 'Ficheiro vazio' });
      if (buf.length > MAX) return send(res, 413, { error: 'Ficheiro demasiado grande (máx. 30 MB)' });
      const id = newId('f_');
      if (r2Ativo()) {
        try {
          const r2url = await r2Put(me.tenant_id + '/' + id, buf, ctype);
          // Regista o ficheiro SEM os bytes (dados NULL) + o r2url — assim o servidor serve-o
          // com sessão (proxy do R2), tal como os migrados, sem depender de bucket público.
          try { db.prepare('INSERT INTO files(id,tenant_id,nome,tipo,dados,criado_em,r2url) VALUES(?,?,?,?,?,?,?)').run(id, me.tenant_id, String(nome || 'ficheiro').slice(0, 200), ctype, null, now(), r2url); } catch (e) {}
          return send(res, 200, { url: _baseUrl(req) + '/api/files/' + id, id: id, store: 'r2' });
        }
        catch (e) { console.warn('[R2] falhou, a guardar no servidor:', e && e.message ? e.message : e); }
      }
      try { Q.insFile.run(id, me.tenant_id, String(nome || 'ficheiro').slice(0, 200), ctype, buf, now()); }
      catch (e) { return send(res, 500, { error: 'Não foi possível guardar o ficheiro' }); }
      return send(res, 200, { url: _baseUrl(req) + '/api/files/' + id, id: id, store: 'db' });
    }
    if (p.startsWith('/api/files/') && req.method === 'GET') {
      // Segurança: o descarregamento de ficheiros EXIGE sessão válida e só devolve
      // ficheiros do PRÓPRIO tenant (impede que alguém com o link aceda a documentos
      // de outra empresa). O cliente envia o token no cabeçalho Authorization ou em ?token=.
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      const id = decodeURIComponent(p.slice('/api/files/'.length));
      const row = id && Q.getFile.get(id);
      if (!row) return send(res, 404, { error: 'Ficheiro não encontrado' });
      if (String(row.tenant_id) !== String(me.tenant_id)) return send(res, 403, { error: 'Sem acesso a este ficheiro' });
      const _nomeOrig = String(row.nome || 'ficheiro');
      // filename clássico: só ASCII imprimível, sem aspas/barra/; — evita "Invalid character in header"
      let _nomeAscii = _nomeOrig.replace(/[^\x20-\x7E]/g, '_').replace(/["\\;]/g, '').trim();
      if (!_nomeAscii) _nomeAscii = 'documento';
      let _tipo = String(row.tipo || 'application/octet-stream').replace(/[^\x20-\x7E]/g, '') || 'application/octet-stream';
      // Só se mostra INLINE o que é seguro (imagens rasterizadas e PDF). Tudo o resto — HTML,
      // SVG (pode conter scripts), etc. — é forçado a descarregar, nunca executado no browser.
      const inlineOk = /^image\/(png|jpe?g|gif|webp|bmp|avif)$/i.test(_tipo) || /^application\/pdf$/i.test(_tipo);
      const disp = inlineOk ? 'inline' : 'attachment';
      let _cd;
      try { _cd = disp + "; filename=\"" + _nomeAscii + "\"; filename*=UTF-8''" + encodeURIComponent(_nomeOrig); } catch (e) { _cd = disp + '; filename="documento"'; }

      // Ficheiro já migrado para o R2: o SERVIDOR busca-o ao R2 (com credenciais, sem precisar
      // de bucket público) e entrega-o. Se isso falhar, tenta o redirecionamento público.
      if ((row.dados == null) && row.r2url) {
        const _objKey = String(row.tenant_id) + '/' + id;
        let _done = false;
        r2GetStream(_objKey, function (r2res) {
          if (r2res.statusCode >= 200 && r2res.statusCode < 300) {
            _done = true;
            var h = { 'Content-Type': _tipo, 'Content-Disposition': _cd, 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
            if (r2res.headers['content-length']) h['Content-Length'] = r2res.headers['content-length'];
            try { res.writeHead(200, h); } catch (e) { try { res.writeHead(200, { 'Content-Type': _tipo }); } catch (_) {} }
            r2res.pipe(res);
          } else {
            r2res.resume();
            if (!_done) { _done = true; try { res.writeHead(302, { 'Location': String(row.r2url), 'Cache-Control': 'private, no-store' }); } catch (e) {} res.end(); }
          }
        }, function () {
          if (!_done) { _done = true; try { res.writeHead(302, { 'Location': String(row.r2url), 'Cache-Control': 'private, no-store' }); res.end(); } catch (e) { try { res.writeHead(502); res.end(); } catch (_) {} } }
        });
        return;
      }
      if (row.dados == null) return send(res, 404, { error: 'Ficheiro não encontrado' });
      const buf = Buffer.from(row.dados);
      const _headers = { 'Content-Type': _tipo, 'Content-Disposition': _cd, 'Content-Length': buf.length, 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
      try {
        res.writeHead(200, _headers);
      } catch (e) {
        // Último recurso: cabeçalho mínimo garantidamente válido
        res.writeHead(200, { 'Content-Type': _tipo, 'Content-Disposition': disp + '; filename="documento"', 'Content-Length': buf.length, 'X-Content-Type-Options': 'nosniff' });
      }
      return res.end(buf);
    }

    // — Armazenamento: estado (administrador) —
    if (p === '/api/admin/storage' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      let c = { n: 0, bytes: 0 }; try { c = Q.filesBlobCount.get(); } catch (e) {}
      const _free = _freeBytes(); const mb = function (n) { return Math.round(n / 1048576 * 10) / 10; };
      let _dbB = 0; try { _dbB = fs.statSync(path.join(DATA_DIR, 'amdp.db')).size; } catch (e) {}
      return send(res, 200, { r2_ativo: r2Ativo(), ficheiros_na_base: Number(c.n || 0), ficheiros_mb: mb(Number(c.bytes || 0)), base_mb: mb(_dbB), espaco_livre_mb: _free >= 0 ? mb(_free) : null });
    }

    // — Migrar comprovativos da base para o R2 (administrador) — por lotes, chamável várias vezes —
    if (p === '/api/admin/migrar-r2' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      if (!r2Ativo()) return send(res, 400, { error: 'O R2 não está configurado. Defina as variáveis R2_* no Railway e recoloque o servidor.' });
      const b = await readBody(req);
      const lote = Math.min(50, Math.max(1, Number(b.lote) || 20));
      let rows = []; try { rows = Q.filesBlobBatch.all(lote); } catch (e) { return send(res, 500, { error: 'Erro a ler ficheiros' }); }
      let migrados = 0, bytes = 0, erros = 0;
      for (const r of rows) {
        try {
          const buf = Buffer.from(r.dados);
          const url = await r2Put(String(r.tenant_id) + '/' + String(r.id), buf, r.tipo || 'application/octet-stream');
          Q.fileSetR2.run(url, r.id);
          migrados++; bytes += buf.length;
        } catch (e) { erros++; try { console.warn('[migrar-r2] falhou ' + r.id + ':', e && e.message ? e.message : e); } catch (_) {} }
      }
      let restam = 0; try { restam = Number(Q.filesBlobCount.get().n || 0); } catch (e) {}
      const mb = function (n) { return Math.round(n / 1048576 * 10) / 10; };
      return send(res, 200, { migrados: migrados, restantes: restam, mb_migrados_agora: mb(bytes), erros: erros });
    }

    // — Compactar a base de dados (VACUUM) para recuperar o espaço já libertado (administrador) —
    if (p === '/api/admin/vacuum' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      let _dbSize = 0; try { _dbSize = fs.statSync(path.join(DATA_DIR, 'amdp.db')).size; } catch (e) {}
      const _free = _freeBytes();
      // O VACUUM precisa de espaço livre ~ ao tamanho da base (cria uma cópia temporária).
      if (_free >= 0 && _dbSize > 0 && _free < _dbSize * 1.1) {
        return send(res, 507, { error: 'Espaço insuficiente para compactar: precisa de cerca de ' + Math.round(_dbSize / 1048576) + ' MB livres. Aumente o volume no Railway temporariamente e tente de novo (depois pode reduzi-lo).' });
      }
      try { db.exec('VACUUM;'); } catch (e) { return send(res, 500, { error: 'Falha ao compactar: ' + (e && e.message ? e.message : e) }); }
      let _novo = 0; try { _novo = fs.statSync(path.join(DATA_DIR, 'amdp.db')).size; } catch (e) {}
      const mb = function (n) { return Math.round(n / 1048576 * 10) / 10; };
      return send(res, 200, { ok: true, base_mb: mb(_novo) });
    }

    // — Diagnóstico do R2: confirma se os ficheiros públicos abrem mesmo (administrador) —
    if (p === '/api/admin/r2-diag' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      if (!r2Ativo()) return send(res, 400, { error: 'O R2 não está configurado.' });
      let _row = null; try { _row = db.prepare("SELECT id,r2url FROM files WHERE tenant_id=? AND r2url IS NOT NULL AND r2url<>'' LIMIT 1").get(me.tenant_id); } catch (e) {}
      const _url = _row && _row.r2url;
      if (!_url) return send(res, 200, { amostra: null, nota: 'Ainda não há ficheiros no R2 para testar.' });
      // 1) LEITURA ASSINADA (o caminho REAL que o sistema usa — não precisa de bucket público).
      const _objKey = String(me.tenant_id) + '/' + String(_row.id);
      const _assin = await new Promise((resolve) => {
        var _d = '';
        r2GetStream(_objKey, function (r) { r.on('data', function (c) { if (_d.length < 300) _d += c.toString(); }); r.on('end', function () { resolve({ status: r.statusCode, corpo: _d.slice(0, 200) }); }); }, function (e) { resolve({ status: -1, corpo: String(e && e.message || e).slice(0, 120) }); });
      });
      // 2) ACESSO PÚBLICO (só informativo — já não é necessário).
      const _pub = await new Promise((resolve) => {
        try { const rq = https.get(_url, (r) => { r.resume(); resolve(r.statusCode); }); rq.on('error', () => resolve(-1)); rq.setTimeout(8000, () => { try { rq.destroy(); } catch (e) {} resolve(-2); }); } catch (e) { resolve(-1); }
      });
      return send(res, 200, {
        amostra: _url, host: R2.host, bucket: R2.bucket,
        assinado_status: _assin.status, assinado_ok: (_assin.status >= 200 && _assin.status < 300), assinado_detalhe: _assin.corpo,
        publico_status: _pub, publico_ok: (_pub >= 200 && _pub < 400)
      });
    }

    // — Terminar sessão de um utilizador à distância (administrador) —
    if (p === '/api/users/logout' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const target = Q.userById.get(String(b.id || ''));
      if (!target || target.tenant_id !== me.tenant_id) return send(res, 404, { error: 'Conta não encontrada' });
      Q.bumpSess.run(target.id, me.tenant_id);
      return send(res, 200, { ok: true });
    }

    // — Cópias de segurança (administrador) —
    if (p === '/api/backups' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      let arr = [];
      try { if (fs.existsSync(BACKUP_DIR)) arr = fs.readdirSync(BACKUP_DIR).filter(f => /^amdp-.*\.db$/.test(f)).sort().reverse().map(f => { const st = fs.statSync(path.join(BACKUP_DIR, f)); return { nome: f, bytes: st.size, data: st.mtime.toISOString() }; }); } catch (e) {}
      return send(res, 200, { backups: arr, keep: BACKUP_KEEP });
    }
    if (p === '/api/backups/run' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const d = fazerBackup();
      return d ? send(res, 200, { ok: true }) : send(res, 500, { error: 'Não foi possível criar a cópia' });
    }
    if (p === '/api/backups/download' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const nome = String(u.searchParams.get('name') || '');
      if (!/^amdp-[\w:-]+\.db$/.test(nome)) return send(res, 400, { error: 'Nome inválido' });
      const fp = path.join(BACKUP_DIR, nome);
      if (!fs.existsSync(fp)) return send(res, 404, { error: 'Cópia não encontrada' });
      const buf = fs.readFileSync(fp);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + nome + '"', 'Content-Length': buf.length });
      return res.end(buf);
    }

    // — Diagnóstico do canal de email (administrador) —
    if (p === '/api/auth/email-config' && req.method === 'GET') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      return send(res, 200, { configurado: !!RESEND_API_KEY, remetente: MAIL_FROM });
    }
    // — Teste de envio de email (administrador) — mostra o motivo real de falha —
    if (p === '/api/auth/test-email' && req.method === 'POST') {
      const me = auth(req); if (!me) return send(res, 401, { error: 'Sessão inválida' });
      if (!isAdmin(me.role)) return send(res, 403, { error: 'Apenas o Administrador' });
      const b = await readBody(req);
      const para = String(b.to || me.email || '').trim();
      if (!para) return send(res, 400, { error: 'Indique o email de destino' });
      if (!RESEND_API_KEY) return send(res, 400, { error: 'RESEND_API_KEY não está definida no servidor.' });
      try {
        await enviarEmailResend(para, 'Teste de email — AMDP',
          '<div style="font-family:Arial,sans-serif;font-size:15px;color:#1a2330"><p>Este é um email de teste do sistema AMDP.</p><p>Se o recebeu, o canal de recuperação de palavra-passe está a funcionar.</p><p style="color:#8a99ab;font-size:12px">Remetente: ' + MAIL_FROM + '</p></div>');
        return send(res, 200, { ok: true, remetente: MAIL_FROM });
      } catch (e) {
        return send(res, 502, { error: 'Falha no envio: ' + (e && e.message ? e.message : String(e)) });
      }
    }

    // — Recuperação de palavra-passe (self-service, por email) —
    if (p === '/api/auth/forgot' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      // anti-spam: no máximo 1 pedido por email por 60s
      const _last = _resetThrottle.get(email) || 0;
      if (email && (Date.now() - _last) > 60000) {
        _resetThrottle.set(email, Date.now());
        const user = Q.userByEmail.get(email);
        if (user && Number(user.ativo) !== 0) {
          const code = String(Math.floor(100000 + Math.random() * 900000));   // 6 dígitos
          const hash = crypto.createHmac('sha256', AUTH_SECRET).update(code).digest('hex');
          try { Q.upsertReset.run(user.id, hash, Date.now() + 30 * 60 * 1000, Date.now()); } catch (e) {}
          try {
            await enviarEmailResend(user.email, 'Recuperação de palavra-passe — AMDP',
              '<div style="font-family:Arial,sans-serif;font-size:15px;color:#1a2330"><p>Olá,</p><p>Recebemos um pedido para repor a palavra-passe da sua conta AMDP.</p><p>O seu código de recuperação é:</p><p style="font-size:26px;font-weight:bold;letter-spacing:3px;color:#1e8fc5">' + code + '</p><p>Este código é válido por <strong>30 minutos</strong>. Se não foi você que pediu, ignore este email — a sua palavra-passe não muda.</p><p style="color:#8a99ab;font-size:12px">AMDP — mensagem automática, não responda.</p></div>');
          } catch (e) { console.warn('[forgot] email não enviado:', e && e.message ? e.message : e); }
        }
      }
      // Resposta genérica — nunca revela se o email existe
      return send(res, 200, { ok: true });
    }
    if (p === '/api/auth/reset' && req.method === 'POST') {
      const b = await readBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const code = String(b.code || '').trim();
      const np = String(b.newPassword || '');
      if (senhaFraca(np)) return send(res, 400, { error: REGRA_SENHA });
      const user = email ? Q.userByEmail.get(email) : null;
      const rr = user ? Q.getReset.get(user.id) : null;
      if (!user || !rr || !rr.expira || Date.now() > Number(rr.expira)) { if (user && rr) { try { Q.delReset.run(user.id); } catch (e) {} } return send(res, 400, { error: 'Código inválido ou expirado' }); }
      if (Number(rr.tentativas) >= 5) { try { Q.delReset.run(user.id); } catch (e) {} return send(res, 429, { error: 'Demasiadas tentativas. Peça um novo código.' }); }
      const hash = crypto.createHmac('sha256', AUTH_SECRET).update(code).digest('hex');
      if (hash !== rr.code_hash) { try { Q.bumpResetTent.run(user.id); } catch (e) {} return send(res, 400, { error: 'Código inválido ou expirado' }); }
      try { Q.updUserPass.run(hashPassword(np), user.id); Q.bumpSess.run(user.id, user.tenant_id); Q.delReset.run(user.id); } catch (e) { return send(res, 500, { error: 'Não foi possível repor a palavra-passe' }); }
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'Endpoint não encontrado' });
  } catch (e) {
    try { console.error('[erro]', e && e.stack ? e.stack : e); } catch (_) {}
    return send(res, 500, { error: 'Erro interno do servidor' });
  }
});

server.listen(PORT, () => {
  console.log('AMDP sync server (node:sqlite) a ouvir na porta ' + PORT + ' · dados em ' + DATA_DIR);
  try { setTimeout(fazerBackup, 60 * 1000); setInterval(fazerBackup, 24 * 60 * 60 * 1000); } catch (e) {}
});
