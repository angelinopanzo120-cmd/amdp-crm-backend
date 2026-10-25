/**
 * ══════════════════════════════════════════════════════════════════
 *  AMDP — Serviço de Cobranças Automáticas (100% AUTÓNOMO)
 * ══════════════════════════════════════════════════════════════════
 *  O servidor CALCULA SOZINHO os devedores (não precisa da app aberta):
 *   1. Lê do backend: clientes, conta corrente, faturas e a configuração.
 *   2. Calcula o saldo de cada cliente = débitos − créditos (igual à app).
 *   3. Para cada cliente com saldo > 0 e fora da cadência, envia lembrete
 *      por WhatsApp (API Meta) e/ou Email (SMTP).
 *   4. Regista o envio (enviadas.json) — respeita a cadência e nunca repete.
 *
 *  MODO alternativo: MODO=fila  → em vez de calcular, envia a fila
 *  (cobrancasFila) preparada na app. Por defeito usa MODO=auto.
 *
 *  Configuração: ver .env.example e GUIA-DEPLOY.md
 * ══════════════════════════════════════════════════════════════════
 */
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import fs from 'fs';

const CFG = {
  BACKEND_URL: process.env.BACKEND_URL || 'https://amdp-crm-backend-production.up.railway.app',
  DADOS_PATH:  process.env.DADOS_PATH  || '/api/dados',
  LOGIN_EMAIL: process.env.LOGIN_EMAIL || '',   // email de administrador (o mesmo que usa para entrar no sistema)
  LOGIN_PASS:  process.env.LOGIN_PASS  || '',   // a senha desse administrador
  HORA_CRON:   process.env.HORA_CRON   || '0 9 1,16 * *',   // dia 1 e dia 16 de cada mês (~de 15 em 15 dias)
  MODO:        (process.env.MODO || 'auto').toLowerCase(),   // 'auto' | 'fila'
  CADENCIA:    Number(process.env.CADENCIA || 15),            // dias entre lembretes (se a app não definir)
  WA_TOKEN:    process.env.WA_TOKEN    || '',
  WA_PHONE_ID: process.env.WA_PHONE_ID || '',
  WA_TEMPLATE: process.env.WA_TEMPLATE || '',
  SMTP_HOST:   process.env.SMTP_HOST   || '',
  SMTP_PORT:   Number(process.env.SMTP_PORT || 587),
  SMTP_USER:   process.env.SMTP_USER   || '',
  SMTP_PASS:   process.env.SMTP_PASS   || '',
  EMAIL_FROM:  process.env.EMAIL_FROM  || 'AMDP <assistencia@amdp.ao>',
  SUGESTOES_EMAIL: process.env.SUGESTOES_EMAIL || 'assistencia@amdp.ao',
  SUG_CRON:    process.env.SUG_CRON || '*/30 * * * *',   // verifica sugestões a cada 30 min
  RESEND_KEY:  process.env.RESEND_KEY || ((process.env.SMTP_PASS||'').indexOf('re_')===0 ? process.env.SMTP_PASS : ''),
  UMA_VEZ:     process.env.EXECUTAR_UMA_VEZ === '1'
};
const EMPRESA = 'AMDP - Comércio e Prestação de Serviços SU, LDA';
const TPL_DEF = 'Exmo(a). Sr(a). {cliente}, da parte da '+EMPRESA+'.\n\nConsta em aberto na sua conta o valor de {valor}. Agradecemos a regularização logo que possível.\n\nCaso o pagamento já tenha sido efetuado, agradecemos que ignore esta mensagem. Obrigado pela preferência.';

const LOG='./enviadas.json';
const lerLog=()=>{ try{ return JSON.parse(fs.readFileSync(LOG,'utf8')); }catch{ return {}; } };
const gravarLog=(o)=>{ try{ fs.writeFileSync(LOG, JSON.stringify(o,null,2)); }catch(e){ console.error('log:',e.message); } };
const log=(...a)=>console.log(new Date().toISOString(), ...a);
const hoje=()=> new Date().toISOString().slice(0,10);
const dias=(a,b)=> Math.floor((new Date(a)-new Date(b))/86400000);

let _token=null;
async function login(){
  if(!CFG.LOGIN_EMAIL || !CFG.LOGIN_PASS) throw new Error('Faltam LOGIN_EMAIL / LOGIN_PASS (email e senha de administrador)');
  const r=await fetch(CFG.BACKEND_URL+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:String(CFG.LOGIN_EMAIL).toLowerCase(),password:CFG.LOGIN_PASS})});
  if(!r.ok) throw new Error('login HTTP '+r.status+(r.status===401?' (email ou senha de administrador errados)':''));
  const j=await r.json(); _token=j&&j.token; if(!_token) throw new Error('login sem token'); return _token;
}
async function snapshot(){
  if(!_token) await login();
  let r=await fetch(CFG.BACKEND_URL+CFG.DADOS_PATH,{headers:{'Authorization':'Bearer '+_token,accept:'application/json'}});
  if(r.status===401){ _token=null; await login(); r=await fetch(CFG.BACKEND_URL+CFG.DADOS_PATH,{headers:{'Authorization':'Bearer '+_token,accept:'application/json'}}); }
  if(!r.ok) throw new Error('backend HTTP '+r.status);
  return await r.json();
}
function col(d,nome){
  const c = d?.[nome] ?? d?.dados?.[nome] ?? d?.['amdp_crm_'+nome] ?? d?.dados?.['amdp_crm_'+nome] ?? d?.data?.['amdp_crm_'+nome] ?? d?.data?.[nome];
  if(Array.isArray(c)) return c;
  if(typeof c==='string'){ try{ const p=JSON.parse(c); if(Array.isArray(p)) return p; }catch{} }
  return [];
}
function fmtKz(v){ try{ return new Intl.NumberFormat('pt-PT').format(Math.round(v||0))+' Kz'; }catch{ return Math.round(v||0)+' Kz'; } }
function telWa(t){ let d=String(t==null?'':t).replace(/[^0-9]/g,''); if(!d) return ''; if(d.startsWith('00'))d=d.slice(2); if(d.startsWith('244'))return d; if(d.length===9)return '244'+d; return d; }

/** Calcula os devedores a partir de clientes + conta corrente (igual à app). */
function calcularDevedores(d){
  const clientes=col(d,'clientes'), cc=col(d,'contacorrente'), facturas=col(d,'facturas');
  const saldo={};
  for(const m of cc){ if(!m) continue; const id=String(m.clienteId); const v=Number(m.valor)||0; saldo[id]=(saldo[id]||0)+(m.tipo==='debito'?v:-v); }
  const venc={}; // vencimento mais antigo por nome de cliente (para {dias})
  for(const f of facturas){ if(!f||!f.emitida||f.anulada||!f.vencimento) continue; const n=String(f.cliente||''); if(!venc[n]||f.vencimento<venc[n]) venc[n]=f.vencimento; }
  const out=[];
  for(const c of clientes){ if(!c||!c.nome) continue; const s=+((saldo[String(c.id)]||0)).toFixed(2); if(s>0){ const v=venc[String(c.nome)]; out.push({cliente:c, saldo:s, dias: v?Math.max(0,dias(hoje(),v)):0}); } }
  return out;
}
function montarMsg(tpl, cliente, saldo, d){
  return String(tpl||TPL_DEF).replace(/\{cliente\}/g,cliente.nome||'').replace(/\{valor\}/g,fmtKz(saldo)).replace(/\{empresa\}/g,EMPRESA).replace(/\{dias\}/g,String(d||0));
}

async function enviarWhatsApp(numero, texto){
  if(!CFG.WA_TOKEN||!CFG.WA_PHONE_ID) throw new Error('WhatsApp não configurado');
  const url=`https://graph.facebook.com/v20.0/${CFG.WA_PHONE_ID}/messages`;
  const body=CFG.WA_TEMPLATE
    ? {messaging_product:'whatsapp',to:numero,type:'template',template:{name:CFG.WA_TEMPLATE,language:{code:'pt_PT'},components:[{type:'body',parameters:[{type:'text',text:texto.slice(0,1024)}]}]}}
    : {messaging_product:'whatsapp',to:numero,type:'text',text:{body:texto}};
  const r=await fetch(url,{method:'POST',headers:{Authorization:'Bearer '+CFG.WA_TOKEN,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error('WhatsApp API: '+(j?.error?.message||r.status)); return j;
}
let _m=null; const mailer=()=>{ if(_m) return _m; if(!CFG.SMTP_HOST) throw new Error('Email não configurado'); _m=nodemailer.createTransport({host:CFG.SMTP_HOST,port:CFG.SMTP_PORT,secure:CFG.SMTP_PORT===465,auth:{user:CFG.SMTP_USER,pass:CFG.SMTP_PASS}}); return _m; };
function _htmlCorpo(texto, html){
  // Se a app enviou HTML formatado (ex.: a própria fatura), usa-se tal e qual;
  // caso contrário, embrulha-se o texto simples para manter a formatação.
  if(html && String(html).trim()) return String(html);
  return '<pre style="font-family:inherit;white-space:pre-wrap">'+String(texto).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))+'</pre>';
}
async function enviarEmailResend(para, assunto, texto, html){
  const r = await fetch('https://api.resend.com/emails', { method:'POST',
    headers:{ 'Authorization':'Bearer '+CFG.RESEND_KEY, 'Content-Type':'application/json' },
    body: JSON.stringify({ from: CFG.EMAIL_FROM, to: [para], subject: assunto, text: texto, html: _htmlCorpo(texto, html) }) });
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error('Resend API: '+(j&&(j.message||j.name)||('HTTP '+r.status)));
  return j;
}
async function enviarEmail(para, assunto, texto, html){
  if(CFG.RESEND_KEY){ return enviarEmailResend(para, assunto, texto, html); }   // via HTTPS (porta 443) — não é bloqueado
  await mailer().sendMail({from:CFG.EMAIL_FROM,to:para,subject:assunto,text:texto,html:_htmlCorpo(texto, html)});
}

async function processarAuto(){
  log('— MODO AUTÓNOMO: a calcular devedores —');
  const d=await snapshot();
  const cfgArr=col(d,'cobrancaConfig'); const cfg=(cfgArr||[]).find(x=>x&&x.id==='config')||{};
  if(cfg.ativo===false){ log('Cobranças automáticas DESATIVADAS na app. A sair.'); return; }
  const cadencia=Number(cfg.cadencia||CFG.CADENCIA)||15;
  const canalWa=(cfg.whatsapp!==false), canalEm=(cfg.email!==false);
  const tpl=cfg.template||TPL_DEF; const assunto=cfg.assunto||'Lembrete de conta em aberto — AMDP';

  const devedores=calcularDevedores(d);
  log('Clientes com dívida:', devedores.length, '| cadência:', cadencia, 'dias');
  const enviadas=lerLog(); let okC=0, skip=0, erroC=0;
  for(const dv of devedores){
    const c=dv.cliente, id='c'+c.id;
    const ult=enviadas[id]?.data;
    if(ult && dias(hoje(),ult.slice(0,10)) < cadencia){ skip++; continue; }  // dentro da cadência
    const msg=montarMsg(tpl,c,dv.saldo,dv.dias);
    let enviouAlgo=false;
    if(canalWa){ const tel=telWa(c.tel||c.telefone||c.telemovel); if(tel){ try{ await enviarWhatsApp(tel,msg); log('  ✓ WhatsApp →',c.nome); enviouAlgo=true; await new Promise(r=>setTimeout(r,1200)); }catch(e){ erroC++; log('  ✗ WhatsApp',c.nome,':',e.message); } } }
    if(canalEm){ if(c.email){ try{ await enviarEmail(c.email,assunto,msg); log('  ✓ Email →',c.nome); enviouAlgo=true; }catch(e){ erroC++; log('  ✗ Email',c.nome,':',e.message); } } }
    if(enviouAlgo){ enviadas[id]={data:new Date().toISOString(),nome:c.nome,saldo:dv.saldo}; okC++; }
  }
  gravarLog(enviadas);
  log(`Concluído (auto): ${okC} cliente(s) contactado(s), ${skip} dentro da cadência, ${erroC} erro(s).`);
}

async function processarFila(){
  log('— MODO FILA: a enviar a fila preparada na app —');
  const d=await snapshot(); const fila=col(d,'cobrancasFila').filter(x=>x&&x.estado==='pendente');
  log('Itens pendentes:', fila.length); const enviadas=lerLog(); let ok=0,err=0;
  for(const it of fila){ const k='q'+it.id; if(enviadas[k]) continue;
    try{ if(it.canal==='whatsapp') await enviarWhatsApp(it.destino,it.mensagem); else await enviarEmail(it.destino,it.assunto||'Lembrete AMDP',it.mensagem);
      enviadas[k]={data:new Date().toISOString(),nome:it.nome,canal:it.canal}; ok++; log('  ✓',it.canal,'→',it.nome); await new Promise(r=>setTimeout(r,1200));
    }catch(e){ err++; log('  ✗',it.canal,'→',it.nome,':',e.message); } }
  gravarLog(enviadas); log(`Concluído (fila): ${ok} enviada(s), ${err} erro(s).`);
}

async function processarSugestoes(){
  if(!CFG.SMTP_HOST){ return; } // email não configurado -> nada a fazer
  let sugs=[]; try{ const d=await snapshot(); sugs=col(d,'sugestoes'); }catch(e){ log('sugestões?', e.message); return; }
  const novas=(sugs||[]).filter(x=>x&&x.mensagem);
  if(!novas.length) return;
  const LBL={bug:'Problema',melhoria:'Melhoria',outro:'Outro'};
  const enviadas=lerLog(); let ok=0,err=0;
  for(const sug of novas){
    const k='sug'+sug.id; if(enviadas[k]) continue;
    const tipo=LBL[sug.tipo]||sug.tipo||'Sugestão';
    const assunto='[AMDP Sistema] '+tipo+' — de '+(sug.de||'utilizador');
    const corpo='Tipo: '+tipo+'\nUtilizador: '+(sug.de||'—')+'\nPágina: '+(sug.pagina||'—')+'\nData: '+(sug.data||'—')+'\n-----------------------------------------\n'+(sug.mensagem||'')+'\n\n(Enviado automaticamente pelo Sistema AMDP)';
    try{ await enviarEmail(CFG.SUGESTOES_EMAIL, assunto, corpo); enviadas[k]={data:new Date().toISOString(),de:sug.de,tipo:sug.tipo}; ok++; log('  ✓ sugestão →',CFG.SUGESTOES_EMAIL,'('+(sug.de||'')+')'); await new Promise(r=>setTimeout(r,600)); }
    catch(e){ err++; log('  ✗ sugestão',sug.id,':',e.message); }
  }
  gravarLog(enviadas);
  if(ok||err) log(`Sugestões: ${ok} enviada(s) para ${CFG.SUGESTOES_EMAIL}, ${err} erro(s).`);
}
async function processarEmailFila(){
  if(!CFG.RESEND_KEY && !CFG.SMTP_HOST) return;
  let fila=[]; try{ const d=await snapshot(); fila=col(d,'emailfila'); }catch(e){ log('emailfila?', e.message); return; }
  const pend=(fila||[]).filter(x=> x && x.para && x.estado==='pendente');
  if(!pend.length) return;
  const enviadas=lerLog(); let ok=0,err=0;
  for(const it of pend){
    const k='ef'+it.id; if(enviadas[k]) continue;
    try{ await enviarEmail(it.para, it.assunto || 'AMDP', it.texto || '', it.html || ''); enviadas[k]={data:new Date().toISOString(), para:it.para, tipo:it.tipo||''}; ok++; log('  ✓ email ('+(it.tipo||'')+') →', it.para); await new Promise(r=>setTimeout(r,800)); }
    catch(e){ err++; log('  ✗ email fila', it.id, ':', e.message); }
  }
  gravarLog(enviadas);
  if(ok||err) log(`Fila de emails: ${ok} enviado(s), ${err} erro(s).`);
}
async function processarLembretes(){
  if(!CFG.RESEND_KEY && !CFG.SMTP_HOST) return;
  let ags=[]; try{ const d=await snapshot(); ags=col(d,'agendamentos'); }catch(e){ log('agendamentos?', e.message); return; }
  const amanha = new Date(Date.now()+86400000).toISOString().slice(0,10);
  const alvo = (ags||[]).filter(a=> a && a.estado==='agendado' && a.lembrete!==false && a.email && a.data===amanha);
  if(!alvo.length) return;
  const LBL={revisao:'revisão/manutenção', entrega:'entrega de viatura', reuniao:'reunião', outro:'marcação'};
  const enviadas=lerLog(); let ok=0,err=0;
  for(const a of alvo){
    const k='agd'+a.id+'_'+a.data; if(enviadas[k]) continue;
    const tipo=LBL[a.tipo]||'marcação';
    const assunto='Lembrete: '+tipo+' amanhã — AMDP';
    const corpo='Exmo(a). Sr(a). '+(a.cliente||'')+',\n\n'
      +'Lembramos que tem uma '+tipo+' agendada para AMANHÃ ('+a.data+(a.hora?(' às '+a.hora):'')+').\n'
      +(a.viatura?('Viatura/ref.: '+a.viatura+'\n'):'')
      +(a.notas?('Notas: '+a.notas+'\n'):'')
      +'\nCaso precise de remarcar, contacte-nos.\n\nAMDP - Comércio e Prestação de Serviços SU, LDA';
    try{ await enviarEmail(a.email, assunto, corpo); enviadas[k]={data:new Date().toISOString(), cliente:a.cliente, tipo:a.tipo}; ok++; log('  ✓ lembrete →', a.email, '('+tipo+')'); await new Promise(r=>setTimeout(r,800)); }
    catch(e){ err++; log('  ✗ lembrete', a.id, ':', e.message); }
  }
  gravarLog(enviadas);
  if(ok||err) log(`Lembretes de marcações: ${ok} enviado(s), ${err} erro(s).`);
}
const ciclo=()=> Promise.all([ (CFG.MODO==='fila'?processarFila():processarAuto()), processarLembretes() ]).catch(e=>log('ERRO ciclo:',e.message));
const cicloSug=()=> Promise.all([processarSugestoes(), processarEmailFila()]).catch(e=>log('ERRO sugestões/emails:',e.message));
log('AMDP Cobranças + Sugestões — serviço iniciado (v2: col fix + email HTML). MODO:', CFG.MODO);
if(CFG.UMA_VEZ){ Promise.all([ciclo(), cicloSug()]).then(()=>process.exit(0)); }
else {
  cron.schedule(CFG.HORA_CRON, ciclo);
  cron.schedule(CFG.SUG_CRON, cicloSug);
  cron.schedule(process.env.LEMBRETE_CRON || '0 8 * * *', function(){ processarLembretes().catch(e=>log('ERRO lembretes:',e.message)); });  // lembretes: todos os dias 08:00
  log('Agendado — cobranças:', CFG.HORA_CRON, '| sugestões:', CFG.SUG_CRON, '(hora do servidor).');
  ciclo(); cicloSug();
}
