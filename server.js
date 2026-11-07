// Ömer IPTV sunucusu: canlı izleyici, yönetici paneli, kanal yönetimi, TV eşleştirme
// Çalıştır:  node server.js        (bağımlılık yok, Node 16+)
// Varsayılan yönetici şifresi: 123456  (değiştirmek için panelden Ayarlar veya ADMIN_PASS=... ile başlat)
// Proxy/HTTPS arkasında gerçek IP için: TRUST_PROXY=1
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PAGE = path.join(__dirname, process.env.PAGE || 'omer-iptv-pro-v6.html');
const DATA = path.join(__dirname, process.env.DATA || 'data.json');

let db = { channels: [], bans: [], announce: '', rev: 1, pass: null };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA, 'utf8')) }; } catch {}
const hashPw = (p, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(String(p), salt, 32).toString('hex') });
if (process.env.ADMIN_PASS || !db.pass) db.pass = hashPw(process.env.ADMIN_PASS || '123456');
const checkPw = p => crypto.timingSafeEqual(crypto.scryptSync(String(p), db.pass.salt, 32), Buffer.from(db.pass.hash, 'hex'));
const save = () => { try { fs.writeFileSync(DATA, JSON.stringify(db)); } catch {} };
save();

const startedAt = Date.now(), viewers = new Map(), tokens = new Map(), tvs = new Map(), hits = new Map(), history = [], log = [];
const TTL = 40000, dayKey = () => new Date().toISOString().slice(0, 10);
let today = dayKey(), peak = 0, uniq = new Set(), tick = 0;
const addLog = m => { log.unshift({ t: Date.now(), m }); if (log.length > 200) log.pop(); };
const limited = (key, max, win) => { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < win); a.push(n); hits.set(key, a); return a.length > max; };
const clientIp = req => { if (TRUST) { const x = req.headers['x-forwarded-for']; if (x) return x.split(',')[0].trim(); } return (req.socket.remoteAddress || '').replace('::ffff:', ''); };
const readBody = req => new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 8192) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const isAdmin = req => { const t = (req.headers.authorization || '').replace(/^Bearer /, ''); return tokens.has(t) && tokens.get(t) > Date.now(); };
const byChannel = () => { const o = {}; for (const v of viewers.values()) { const k = v.ch || '—'; o[k] = (o[k] || 0) + 1; } return o; };
const httpUrl = s => /^https?:\/\/[^\s]{3,500}$/i.test(String(s || ''));

setInterval(() => {
  const n = Date.now();
  if (dayKey() !== today) { today = dayKey(); peak = 0; uniq = new Set(); }
  for (const [id, v] of viewers) if (n - v.seen > TTL) { viewers.delete(id); addLog(`${v.ip} ayrıldı`); }
  for (const [t, e] of tokens) if (e < n) tokens.delete(t);
  for (const [k, a] of hits) { const f = a.filter(t => n - t < 600000); f.length ? hits.set(k, f) : hits.delete(k); }
  if (++tick % 3 === 0) { history.push(viewers.size); if (history.length > 120) history.shift(); }
}, 10000);

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  const url = new URL(req.url, 'http://x'), p = url.pathname, ip = clientIp(req);
  try {
    if (db.bans.includes(ip) && !p.startsWith('/api/admin') && p !== '/api/login') { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Erişim engellendi.'); }
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return fs.createReadStream(PAGE).pipe(res); }
    if (req.method === 'GET' && p === '/api/channels') return json(res, 200, { rev: db.rev, channels: db.channels.map(c => ({ ad: c.ad, url: Buffer.from(c.url).toString('base64'), logo: c.logo, cat: c.cat })) });
    if (req.method === 'POST' && p === '/api/hb') {
      const b = await readBody(req);
      if (!/^[A-Za-z0-9-]{8,64}$/.test(b.id || '')) return json(res, 400, {});
      if (limited('hb' + ip, 60, 60000)) return json(res, 429, {});
      const old = viewers.get(b.id), ch = String(b.ch || '').slice(0, 60);
      if (!old) addLog(`${ip} katıldı → ${ch || '—'}`); else if (old.ch !== ch) addLog(`${ip} kanal değiştirdi → ${ch}`);
      viewers.set(b.id, { ip, ch, ua: String(req.headers['user-agent'] || '').slice(0, 160), since: old ? old.since : Date.now(), seen: Date.now() });
      uniq.add(ip); peak = Math.max(peak, viewers.size);
      return json(res, 200, { online: viewers.size, announce: db.announce, by: byChannel(), rev: db.rev });
    }
    if (req.method === 'POST' && p === '/api/bye') { const b = await readBody(req), v = viewers.get(b.id); if (v) { viewers.delete(b.id); addLog(`${v.ip} ayrıldı`); } return json(res, 200, {}); }
    if (req.method === 'POST' && p === '/api/login') {
      if (limited('login' + ip, 10, 600000)) return json(res, 429, {});
      const b = await readBody(req);
      if (!checkPw(b.pass || '')) { addLog(`Başarısız yönetici girişi: ${ip}`); return json(res, 401, {}); }
      const t = crypto.randomBytes(24).toString('hex'); tokens.set(t, Date.now() + 12 * 3600e3); addLog(`Yönetici girişi: ${ip}`); return json(res, 200, { token: t });
    }
    if (p.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return json(res, 401, {});
      const b = req.method === 'POST' ? await readBody(req) : {};
      if (p === '/api/admin/overview') {
        const n = Date.now();
        return json(res, 200, {
          online: viewers.size, peak, uniqueToday: uniq.size, uptime: Math.round((n - startedAt) / 1000), history, byChannel: byChannel(),
          viewers: [...viewers.values()].sort((a, c) => a.since - c.since).map(v => ({ ip: v.ip, ch: v.ch, ua: v.ua, sec: Math.round((n - v.since) / 1000), since: v.since })),
          bans: db.bans, log: log.slice(0, 100), channels: db.channels, announce: db.announce
        });
      }
      if (p === '/api/admin/announce') { db.announce = String(b.text || '').slice(0, 200); save(); addLog('Duyuru güncellendi'); return json(res, 200, {}); }
      if (p === '/api/admin/channel/add') {
        const ad = String(b.ad || '').trim().slice(0, 60), cat = String(b.cat || 'Genel').trim().slice(0, 30) || 'Genel';
        if (!ad || !httpUrl(b.url) || (b.logo && !httpUrl(b.logo))) return json(res, 400, { error: 'Ad ve geçerli http(s) adresi gerekli' });
        db.channels.push({ id: crypto.randomBytes(6).toString('hex'), ad, url: b.url.trim(), logo: b.logo ? b.logo.trim() : '', cat }); db.rev++; save(); addLog(`Kanal eklendi: ${ad} (${cat})`); return json(res, 200, {});
      }
      if (p === '/api/admin/channel/delete') { const c = db.channels.find(x => x.id === b.id); db.channels = db.channels.filter(x => x.id !== b.id); db.rev++; save(); if (c) addLog(`Kanal silindi: ${c.ad}`); return json(res, 200, {}); }
      if (p === '/api/admin/ban') { const t = String(b.ip || ''); if (t && !db.bans.includes(t)) { db.bans.push(t); save(); addLog(`IP engellendi: ${t}`); for (const [id, v] of viewers) if (v.ip === t) viewers.delete(id); } return json(res, 200, {}); }
      if (p === '/api/admin/unban') { db.bans = db.bans.filter(x => x !== b.ip); save(); addLog(`Engel kaldırıldı: ${b.ip}`); return json(res, 200, {}); }
      if (p === '/api/admin/password') { if (String(b.pass || '').length < 6) return json(res, 400, { error: 'En az 6 karakter' }); db.pass = hashPw(b.pass); save(); addLog('Yönetici şifresi değiştirildi'); return json(res, 200, {}); }
      return json(res, 404, {});
    }
    // ---- TV eşleştirme ----
    if (req.method === 'POST' && p === '/api/tv/register') {
      if (limited('tvreg' + ip, 20, 600000)) return json(res, 429, {});
      let code; do { code = String(crypto.randomInt(1000, 10000)); } while (tvs.has(code));
      const t = { key: crypto.randomBytes(12).toString('hex'), res: null, del: null }; tvs.set(code, t);
      t.del = setTimeout(() => { if (!t.res) tvs.delete(code); }, 600000); return json(res, 200, { code, key: t.key });
    }
    if (req.method === 'GET' && p === '/api/tv/events') {
      const code = url.searchParams.get('code'), t = tvs.get(code);
      if (!t || t.key !== url.searchParams.get('key')) return json(res, 403, {});
      clearTimeout(t.del); res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' }); res.write('retry: 2000\n\n'); t.res = res;
      const ping = setInterval(() => res.write(': ping\n\n'), 25000);
      req.on('close', () => { clearInterval(ping); if (t.res === res) { t.res = null; t.del = setTimeout(() => { if (!t.res) tvs.delete(code); }, 120000); } }); return;
    }
    if (req.method === 'POST' && p === '/api/tv/send') {
      if (limited('tv' + ip, 180, 60000)) return json(res, 429, {});
      const b = await readBody(req), t = tvs.get(String(b.code || ''));
      if (!t || !t.res) { if (limited('tvbad' + ip, 10, 300000)) return json(res, 429, {}); return json(res, 404, {}); }
      const c = b.cmd || {};
      if (!['paired', 'play', 'pause', 'resume', 'mute', 'volup', 'voldown', 'next', 'prev', 'live'].includes(c.t)) return json(res, 400, {});
      t.res.write('data: ' + JSON.stringify({ t: c.t, i: Number.isInteger(c.i) && c.i >= 0 && c.i < 500 ? c.i : undefined }) + '\n\n'); return json(res, 200, {});
    }
    json(res, 404, {});
  } catch (e) { try { json(res, 500, {}); } catch {} }
}).listen(PORT, '0.0.0.0', () => console.log(...));   (yönetici şifresi: ${process.env.ADMIN_PASS ? 'ADMIN_PASS' : '123456'})`));
