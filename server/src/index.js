/* Medidas Pro — API (Cloudflare Worker + D1)
   Guarda a biblioteca de produtos e os anúncios, sincronizados entre os usuários.
   Auth: senha com PBKDF2 + token assinado por HMAC (stateless). */
'use strict';

const ALLOW_ORIGINS = [
  'https://bruneraaas.github.io',
  'http://localhost:8642', 'http://127.0.0.1:8642',
  'http://localhost:8787'
];

function cors(origin){
  const o = ALLOW_ORIGINS.includes(origin) ? origin : ALLOW_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

/* ---- helpers cripto ---- */
const enc = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
const hexToBuf = hex => new Uint8Array(hex.match(/.{2}/g).map(h => parseInt(h,16)));
function b64url(buf){
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s=''; for(const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlToStr(s){
  s = s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='=';
  return atob(s);
}

async function pbkdf2(password, saltHex){
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt: hexToBuf(saltHex), iterations: 100000, hash:'SHA-256' }, key, 256);
  return toHex(bits);
}
async function hmac(msg, secret){
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
async function makeToken(username, secret){
  const payload = b64url(enc.encode(JSON.stringify({ u: username, exp: Date.now() + 45*24*3600*1000 })));
  return payload + '.' + await hmac(payload, secret);
}
async function verifyToken(token, secret){
  if(!token || token.indexOf('.') < 0) return null;
  const [payload, sig] = token.split('.');
  if(sig !== await hmac(payload, secret)) return null;
  try { const d = JSON.parse(b64urlToStr(payload)); return d.exp > Date.now() ? d.u : null; }
  catch { return null; }
}

const rowToItem = r => ({
  id: r.id, kind: r.kind, name: r.name, status: r.status,
  data: JSON.parse(r.data || '{}'),
  deleted: !!r.deleted, updated_at: r.updated_at, updated_by: r.updated_by
});

export default {
  async fetch(request, env){
    const url = new URL(request.url);
    const headers = cors(request.headers.get('Origin') || '');
    const json = (obj, status=200) =>
      new Response(JSON.stringify(obj), { status, headers: { ...headers, 'Content-Type':'application/json' } });

    if(request.method === 'OPTIONS') return new Response(null, { headers });
    if(!env.SECRET) return json({ error: 'Servidor sem SECRET configurado' }, 500);

    const p = url.pathname.replace(/\/+$/,'') || '/';

    try {
      if(p === '/' || p === '/api/ping') return json({ ok:true, service:'medidas-api' });

      /* -------- REGISTRO -------- */
      if(p === '/api/register' && request.method === 'POST'){
        const { username, password, invite } = await request.json();
        if(env.INVITE_CODE && invite !== env.INVITE_CODE)
          return json({ error: 'Código de convite inválido.' }, 403);
        const u = (username||'').trim().toLowerCase();
        if(!u || !password || password.length < 4)
          return json({ error: 'Informe usuário e senha (mínimo 4 caracteres).' }, 400);
        const exists = await env.DB.prepare('SELECT username FROM users WHERE username=?').bind(u).first();
        if(exists) return json({ error: 'Esse usuário já existe.' }, 409);
        const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
        const hash = await pbkdf2(password, salt);
        await env.DB.prepare('INSERT INTO users(username,salt,hash,created_at) VALUES(?,?,?,?)')
          .bind(u, salt, hash, Date.now()).run();
        return json({ token: await makeToken(u, env.SECRET), username: u });
      }

      /* -------- LOGIN -------- */
      if(p === '/api/login' && request.method === 'POST'){
        const { username, password } = await request.json();
        const u = (username||'').trim().toLowerCase();
        const row = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(u).first();
        if(!row) return json({ error: 'Usuário ou senha incorretos.' }, 401);
        const hash = await pbkdf2(password || '', row.salt);
        if(hash !== row.hash) return json({ error: 'Usuário ou senha incorretos.' }, 401);
        return json({ token: await makeToken(u, env.SECRET), username: u });
      }

      /* -------- auth obrigatório abaixo -------- */
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i,'');
      const user = await verifyToken(token, env.SECRET);
      if(!user) return json({ error: 'Sessão expirada. Entre novamente.' }, 401);

      /* -------- LISTAR (sincronização) -------- */
      if(p === '/api/items' && request.method === 'GET'){
        const kind = url.searchParams.get('kind');
        const since = parseInt(url.searchParams.get('since') || '0', 10);
        const q = kind
          ? env.DB.prepare('SELECT * FROM items WHERE kind=? AND updated_at>? ORDER BY updated_at DESC').bind(kind, since)
          : env.DB.prepare('SELECT * FROM items WHERE updated_at>? ORDER BY updated_at DESC').bind(since);
        const { results } = await q.all();
        return json({ items: (results||[]).map(rowToItem), now: Date.now() });
      }

      /* -------- SALVAR / ATUALIZAR -------- */
      if(p === '/api/items' && request.method === 'PUT'){
        const it = await request.json();
        if(!it || !it.id) return json({ error: 'id obrigatório' }, 400);
        const now = Date.now();
        await env.DB.prepare(
          `INSERT INTO items(id,kind,name,status,data,deleted,updated_at,updated_by)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET
             kind=excluded.kind, name=excluded.name, status=excluded.status,
             data=excluded.data, deleted=excluded.deleted,
             updated_at=excluded.updated_at, updated_by=excluded.updated_by`)
          .bind(it.id, it.kind||'listing', it.name||'', it.status||'draft',
                JSON.stringify(it.data||{}), it.deleted?1:0, now, user).run();
        return json({ ok:true, updated_at: now });
      }

      /* -------- APAGAR (soft delete p/ sincronizar remoção) -------- */
      const mId = p.match(/^\/api\/items\/(.+)$/);
      if(mId && request.method === 'DELETE'){
        const now = Date.now();
        await env.DB.prepare('UPDATE items SET deleted=1, updated_at=?, updated_by=? WHERE id=?')
          .bind(now, user, decodeURIComponent(mId[1])).run();
        return json({ ok:true, updated_at: now });
      }

      return json({ error: 'Rota não encontrada' }, 404);
    } catch(e){
      return json({ error: String((e && e.message) || e) }, 500);
    }
  }
};
